#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

#pragma region THE ORAL CIGNATURES

MODULEENTRY32 GetOsuAuthModule()
{
    MODULEENTRY32 modEntry = { 0 };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!_wcsicmp(modEntry.szModule, L"osu!auth.dll"))
                {
                    CloseHandle(hSnap);

                    return modEntry;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }

    CloseHandle(hSnap);
    return modEntry;
}

char* ScanSignature(char* pattern, char* mask, char* begin, unsigned int size)
{
    unsigned int patternLength = strlen(pattern);

    for (unsigned int i = 0; i < size - patternLength; i++)
    {
        bool found = true;
        for (unsigned int j = 0; j < patternLength; j++)
        {
            if (mask[j] != '?' && pattern[j] != *(begin + i + j))
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return (begin + i);
        }
    }
    return nullptr;
}

#pragma endregion

void Hook(void* src, void* dest)
{
    BYTE stub[] = {
        //pushad
        0x60,
        //mov eax, 0x00000000
        0xB8, 0x00, 0x00, 0x00, 0x00,
        //call eax
        0xFF, 0xD0,
        //popad
        0x61,
        //ret
        0xC3,
    };

    DWORD dwOld;
    VirtualProtect(src, sizeof(stub), PAGE_READWRITE, &dwOld);

    memcpy(src, &stub, sizeof(stub));
    *(DWORD*)((DWORD)src + 2) = (DWORD)dest;

    VirtualProtect(src, sizeof(stub), dwOld, &dwOld);
}

void OnAuthDetect()
{
    std::cout << "Your account has been flagged :)" << std::endl;
}

DWORD __stdcall MainThread(LPVOID param)
{
    AllocConsole();
    SetConsoleTitleA("Denbai Detector");

    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);

    MODULEENTRY32 osuAuthModule = GetOsuAuthModule();

    char* hookAddress = ScanSignature(const_cast<char*>("\x8B\x45\xE8\x89\x45\xC0\xC7\x45\xFC\xFF\xFF\xFF\xFF\x8D\x4D\xC4\xE8\xBB\x06\x5A\x00\x8B\x45\xC0\x8B\x4D\xF4\x64\x89\x0D\x00\x00\x00\x00\x8B\xE5\x5D\xC3"), const_cast<char*>("xxxxxxxxx????xxxx????xxxxxxxxx????xxxx"), (char*)osuAuthModule.modBaseAddr, osuAuthModule.modBaseSize);

    Hook((void*)(hookAddress + 0x25), OnAuthDetect);

    return NULL;
}

BOOL __stdcall DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
        CreateThread(NULL, NULL, MainThread, hModule, NULL, NULL);

    return TRUE;
}

