#include "stdafx.hpp"
#include "dynsec/init/init.hpp"

__declspec(dllexport) void InitializeClient(void* pDynsecData) {
    // caller checks here
    return Dynsec::Init::InitializeClient(static_cast<Dynsec::InitTypes::Callbacks*>(pDynsecData));
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // init
    }

    return TRUE;
}