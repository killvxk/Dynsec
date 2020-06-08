#include "init.hpp"
#include "routines/routines.hpp"
#include "tls_manager.hpp"
#include "global/variables.hpp"
#include "utils/secure/syscall.hpp"
#include "utils/secure/virtual.hpp"

extern "C" void __fastcall hook_wrapper(VOID);

namespace Dynsec::Init {
	void InitializeClient(Dynsec::InitTypes::Callbacks* pCallbacks) {
		// initialized from client
		printf("InitializeClient\n");
	}

	void Initialize() {
		// Initialize our hacky TLS Callback
		GetTLSManager()->RegisterCallback(Global::Vars::g_ModuleHandle, Dynsec::Routines::ThreadLocalStorageCallback);

		// Initialize our syscall monitor
		PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallback;
#ifdef _WIN64
		InstrumentationCallback = { 0, 0, hook_wrapper };
#else
		InstrumentationCallback = { 1, 0, hook_wrapper };
#endif
		Utils::Secure::GetSyscalls()->NtSetInformationProcess(GetCurrentProcess(), PROCESS_INSTRUMENTATION_CALLBACK, &InstrumentationCallback, sizeof(InstrumentationCallback));

		auto MemoryPages = Utils::Secure::GetMemoryPages();
		for (auto& Page : MemoryPages) {
			printf("Page: %llx -> %llx\n", Page.BaseAddress, (uint64_t)Page.BaseAddress + Page.RegionSize);
		}
	}
}