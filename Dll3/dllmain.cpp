#include <Windows.h>
#include <vector>
#include <psapi.h> 
#include "pch.h"
#include "ModUtils.h"

// Link against psapi.lib
#pragma comment(lib, "psapi.lib")

// --- 1. Fixed Scanner ---
uintptr_t FindPattern(HMODULE hModule, const char* pattern, int offset) {
    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO)))
        return 0;

    uintptr_t start = (uintptr_t)modInfo.lpBaseOfDll;
    uintptr_t size = (uintptr_t)modInfo.SizeOfImage;

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
        if (match) return (uintptr_t)(s + offset);
    }
    return 0;
}

// --- 2. Patch Memory ---
bool PatchMemory(uintptr_t address, const char* newBytes, size_t length)
{
    if (!address) return false;

    DWORD oldProtect;
    if (!VirtualProtect((void*)address, length, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    for (size_t i = 0; i < length; ++i) {
        unsigned char byte = strtoul(&newBytes[i * 3], nullptr, 16); // each byte is 2 hex + space
        *((unsigned char*)address + i) = byte;
    }

    VirtualProtect((void*)address, length, oldProtect, &oldProtect);
    return true;
}

// --- 3. Main Logic ---
DWORD WINAPI MainThread(LPVOID lpParam)
{
    Sleep(100);

    struct PatchInfo {
        const char* pattern;
        int offset;
        const char* newBytes;
        size_t length;
    };

    PatchInfo patches[] = {
        { "c6 80 28 01 00 00 01 c6 80 34 01 00 00 01 48 8b 41 78 48 85 c0 e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? c6 44 24 28 01 88 44 24 20", 98, "90 90 90 90 90 90 90", 7 },
        { "c6 45 97 02 c7 45 9f 0b 00 00 00 c6 45 a3 01 48 8d 05 ?? ?? ?? ??", 15, "90 90 90 90 90 90 90", 7 }
    };

    for (auto& p : patches)
    {
        uintptr_t address = FindPattern(GetModuleHandle(NULL), p.pattern, p.offset);
        if (address)
        {
            PatchMemory(address, p.newBytes, p.length);
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
