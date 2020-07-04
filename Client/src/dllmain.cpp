#include "stdafx.hpp"
#include "dynsec/init/init.hpp"
#include "utils/secure/syscall.hpp"
#include "utils/secure/resolved.hpp"
#include "utils/secure/virtual.hpp"
#include "global/variables.hpp"
#include "utils/utils.hpp"
#include "utils/threads/thread_pool.hpp"

extern "C" __declspec(dllexport) void __stdcall InitializeClient(void* pDynsecData) {
	// caller checks here
	return Dynsec::Init::InitializeClient(static_cast<Dynsec::InitTypes::GameDataInit*>(pDynsecData));
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		Global::Vars::g_ModuleHandle = hModule;
		srand((unsigned int)time(0));

		if (!Utils::Secure::GetSyscalls()->Initialize()) {
			printf("failed GetSyscalls()->Initialize\n");
			return FALSE;
		}

		if (!Utils::Secure::GetResolved()->Initialize()) {
			printf("failed GetResolved()->Initialize\n");
			return FALSE;
		}

		Utils::Threads::GetThreadPool()->CreateThread(0xBEEF, Dynsec::Init::Initialize, nullptr);
	}

	return TRUE;
}