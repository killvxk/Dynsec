#include "stdafx.hpp"
#include "dynsec/init/init.hpp"
#include "utils/secure/module.hpp"
#include "utils/secure/syscall.hpp"
#include "utils/secure/virtual.hpp"
#include "utils/structs.hpp"
#include "dynsec/network/network_socket.hpp"
#include "utils/secure/pointers.hpp"

extern "C" {
	__declspec(dllexport) void InitializeClient(void* pDynsecData) {
		// caller checks here
		return Dynsec::Init::InitializeClient(static_cast<Dynsec::InitTypes::Callbacks*>(pDynsecData));
	}
}

#pragma region Temporary
extern "C" void __fastcall hook_wrapper(VOID);
bool g_isProcessingSyscall = false;
extern "C" void __fastcall hook_routine(uintptr_t rcx/*return addr*/, uintptr_t rdx/*return result*/) {
	// We want to avoid having a recursion issue if we call other system functions in here
	if (g_isProcessingSyscall) 
		return;

	g_isProcessingSyscall = 1;
	{
		printf("Syscall returning to %p with result %08x\n", rcx, rdx);
	}
	g_isProcessingSyscall = 0;
}

void SetupInstrumentationCallback() {
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION cb = { 0, 0, hook_wrapper };
	// Change Version to 1 for x32
	// handle -1 == current process
	Utils::Secure::GetSyscalls()->NtSetInformationProcess((HANDLE)-1, PROCESS_INSTRUMENTATION_CALLBACK, &cb, sizeof(cb));
}
#pragma endregion

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        if (!Utils::Secure::GetSyscalls()->Initialize()) {
            printf("failed GetSyscalls()->Initialize\n");
            return FALSE;
        }

		uint64_t* value = new uint64_t;
		*value = 123;
		printf("ptr: %llx\n", (uint64_t)value);

		uint64_t encoded = (uint64_t)EncodePtr(value);
		printf("encoded: %llx\n", encoded);
		printf("decoded: %llx\n", (uint64_t)DecodePtr((void*)encoded));

		delete value;

		SetupInstrumentationCallback();

        auto alloc = Utils::Secure::VirtualAlloc(0, 0x10, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        printf("test allocated: %llx\n", alloc);
        if (alloc) VirtualFree(alloc, 0, MEM_RELEASE);
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        Utils::Secure::GetSyscalls()->Clean();
    }

    return TRUE;
}