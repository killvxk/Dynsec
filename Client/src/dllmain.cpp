#include "stdafx.hpp"
#include "dynsec/init/init.hpp"
#include "utils/secure/module.hpp"
#include "utils/secure/syscall.hpp"
#include "utils/secure/virtual.hpp"

extern "C" {
	__declspec(dllexport) void InitializeClient(void* pDynsecData) {
		// caller checks here
		return Dynsec::Init::InitializeClient(static_cast<Dynsec::InitTypes::Callbacks*>(pDynsecData));
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        if (!Utils::Secure::GetSyscalls()->Initialize()) {
            printf("failed GetSyscalls()->Initialize\n");
            return FALSE;
        }

        auto alloc = Utils::Secure::VirtualAlloc(0, 0x10, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        printf("test allocated: %llx\n", alloc);
        if (alloc) VirtualFree(alloc, 0, MEM_RELEASE);
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        Utils::Secure::GetSyscalls()->Clean();
    }

    return TRUE;
}