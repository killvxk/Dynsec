#include "routines.hpp"
#include "global/variables.hpp"
#include "utils/utils.hpp"

#include "utils/secure/virtual.hpp"

namespace Dynsec::Routines {
	void NTAPI ThreadLocalStorageCallback(PVOID DllHandle, DWORD dwReason, PVOID) {
		if (dwReason == DLL_THREAD_ATTACH) {
			printf("Thread created with DLL_THREAD_ATTACH at \n", Utils::GetThreadEntryPoint(GetCurrentThread()));
		}
	}

	// This causes a lock randomly with the code thats inside :(
	extern "C" void __fastcall hook_routine(uintptr_t rcx /*return addr*/, uintptr_t rdx /*return result*/) {
		// We want to avoid having a recursion issue if we call other system functions in here
		if (Global::Vars::g_ProcessingSyscallCallback[GetCurrentThread()]) {
			return;
		}

		Global::Vars::g_ProcessingSyscallCallback[GetCurrentThread()] = true;

		// handle syscall here

		Global::Vars::g_ProcessingSyscallCallback[GetCurrentThread()] = false;
	}
}