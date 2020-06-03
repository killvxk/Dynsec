#include "stdafx.hpp"
#include "dynsec/init/init.hpp"

__declspec(dllexport) void InitializeClient(void* pDynsecData) {
    // caller checks here
    return Dynsec::Init::InitializeClient(static_cast<Dynsec::InitTypes::Callbacks*>(pDynsecData));
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
#if _DEBUG
        FILE* stream;
        AllocConsole();
        freopen_s(&stream, "CONIN$", "w", stdin);
        freopen_s(&stream, "CONOUT$", "w", stdout);
        freopen_s(&stream, "CONOUT$", "w", stderr);
#endif
    }

    return TRUE;
}