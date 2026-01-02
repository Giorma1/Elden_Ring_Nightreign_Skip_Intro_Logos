#include <Windows.h>
#include <vector>
#include <psapi.h> 
#include "pch.h"
#include "ModUtils.h"
// Link against psapi.lib
#pragma comment(lib, "psapi.lib")

// --- 1. Fixed Scanner (Scans only Game EXE, not System DLLs) ---
uintptr_t FindPattern(HMODULE hModule, const char* pattern, int offset) {
    // Get Module Info
    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO)))
        return 0;

    uintptr_t start = (uintptr_t)modInfo.lpBaseOfDll;
    uintptr_t size = (uintptr_t)modInfo.SizeOfImage;

    // Parse Pattern
    std::vector<int> bytes;
    for (const char* c = pattern; *c; ++c) {
        if (*c == '?') {
            bytes.push_back(-1);
            if (*(c + 1) == '?') ++c;
        }
        else if (*c == ' ') continue;
        else {
            bytes.push_back(strtoul(c, nullptr, 16));
            while (*(c + 1) && *(c + 1) != ' ' && *(c + 1) != '?') ++c;
        }
    }

    // Scan
    unsigned char* s = (unsigned char*)start;
    unsigned char* end = s + size - bytes.size();

    for (; s < end; ++s) {
        bool match = true;
        for (size_t i = 0; i < bytes.size(); ++i) {
            if (bytes[i] != -1 && s[i] != (unsigned char)bytes[i]) {
                match = false;
                break;
            }
        }
        if (match) return (uintptr_t)(s + offset); // RETURN START + OFFSET
    }
    return 0;
}

// --- 2. Main Logic ---
DWORD WINAPI MainThread(LPVOID lpParam)
{
    // Wait 100ms for memory to settle
    Sleep(100);

    
    
    const char* pattern = "48 8b 90 ? ? ? ? 48 85 d2 74 ? c6 82 ? ? ? ? ? e8 ? ? ? ?";

    // The target is 243 bytes from the start of the pattern
    int offset = 243;

    uintptr_t patchAddress = FindPattern(GetModuleHandle(NULL), pattern, offset);

    if (patchAddress != 0)
    {
        // Safety Check: Verify the byte at the address is actually a CALL
        if (*(unsigned char*)patchAddress == 0xE8)
        {
            DWORD oldProtect;
            if (VirtualProtect((void*)patchAddress, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                // Write 5 NOPs (0x90)
                memset((void*)patchAddress, 0x90, 5);
                VirtualProtect((void*)patchAddress, 5, oldProtect, &oldProtect);

                
                
            }
        }
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
