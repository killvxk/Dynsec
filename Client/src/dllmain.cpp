#include "stdafx.hpp"
#include "dynsec/init/init.hpp"
#include "utils/secure/module.hpp"
#include "utils/secure/syscall.hpp"
#include "utils/secure/virtual.hpp"
#include "utils/structs.hpp"
#include "dynsec/network/network_socket.hpp"
#include "utils/secure/pointers.hpp"
#include "dynsec/shellcode/shellcode.hpp"
#include "global/variables.hpp"
#include "../TLSManager.h"

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
	Utils::Secure::GetSyscalls()->NtSetInformationProcess(GetCurrentProcess(), PROCESS_INSTRUMENTATION_CALLBACK, &cb, sizeof(cb));
}
#pragma endregion

DWORD WINAPI TestThread(LPVOID arg) {
	printf("I'm running with arg=%llx, PID %x and TID %x\n", arg, GetCurrentProcessId(), GetCurrentThreadId());
	return 0;
}

void NTAPI OnTlsEvent(PVOID DllHandle, DWORD dwReason, PVOID) {
	printf("============================TLS registered\n");
}
void NTAPI OnTlsEvent2(PVOID DllHandle, DWORD dwReason, PVOID) {
	printf("============================TLS registered V2\n");
}



DWORD WINAPI MainThread(LPVOID) {
	//SetupTLS();
	GetTLSManager()->RegisterCallback(Global::Vars::g_ModuleHandle, OnTlsEvent);
	GetTLSManager()->RegisterCallback(Global::Vars::g_ModuleHandle, OnTlsEvent2);

	uint64_t* value = new uint64_t;
	*value = 123;
	printf("ptr: %llx\n", (uint64_t)value);

	uint64_t encoded = (uint64_t)EncodePtr(value);
	printf("encoded: %llx\n", encoded);
	printf("decoded: %llx\n", (uint64_t)DecodePtr((void*)encoded));

	delete value;

	auto alloc = Utils::Secure::VirtualAlloc(0, 0x10, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("test allocated: %llx\n", alloc);
	if (alloc) printf("virtualfree resp: %i\n", Utils::Secure::VirtualFree(alloc, 0, MEM_RELEASE));
	printf("Heap: %llx\n", ProcessEnvironmentBlock->ProcessHeap);


	Dynsec::Shellcode::Execute((void*)0);

	DWORD tid = 0;
	Utils::Secure::CreateThread(0, TestThread, (PVOID)0x1337, 0, &tid);
	printf("New thread is at %x\n", tid);

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		Global::Vars::g_ModuleHandle = hModule;

		srand((unsigned int)time(0));

		if (!Utils::Secure::GetSyscalls()->Initialize()) {
			printf("failed GetSyscalls()->Initialize\n");
			return FALSE;
		}

		Utils::Secure::CreateThread(0, MainThread, 0, 0, 0);
		// SetupInstrumentationCallback();
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
		Utils::Secure::GetSyscalls()->Clean();
	}

	return TRUE;
}