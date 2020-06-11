#include "init.hpp"
#include "routines/routines.hpp"
#include "tls_manager.hpp"
#include "global/variables.hpp"
#include "utils/secure/syscall.hpp"
#include "utils/secure/virtual.hpp"
#include "utils/threads/thread_pool.hpp"
#include "utils/secure/pointers.hpp"
#include "utils/utils.hpp"

extern "C" void __fastcall hook_wrapper(VOID);

namespace Dynsec::Init {
	void InitializeClient(Dynsec::InitTypes::GameDataInit* InitData) {
		// initialized from client
		Global::Vars::g_GameDataInit = (Dynsec::InitTypes::GameDataInit*)EncodePtr(InitData);

		printf("[Game] -> InitializeClient (%llx)\n", InitData);
	}

	void Initialize(LPVOID lpParam) {
		// Initialize our hacky TLS Callback
		GetTLSManager()->RegisterCallback(Global::Vars::g_ModuleHandle, Dynsec::Routines::ThreadLocalStorageCallback);

		// Initialize our syscall monitor
		PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallback;
#ifdef _WIN64
		InstrumentationCallback = { 0, 0, hook_wrapper };
#else
		InstrumentationCallback = { 1, 0, hook_wrapper };
#endif

		// Utils::Secure::GetSyscalls()->NtSetInformationProcess(GetCurrentProcess(), PROCESS_INSTRUMENTATION_CALLBACK, &InstrumentationCallback, sizeof(InstrumentationCallback));

		// Temp add a sig
		Global::Vars::g_MemorySignatures.push_back({ 0x1, { 0x5B, 0x47, 0x61, 0x6D, 0x65, 0x5D, 0x20, 0x2D, 0x3E, 0x20, 0x49, 0x6E, 0x69, 0x74, 0x69, 0x61, 0x6C, 0x69, 0x7A, 0x65, 0x43, 0x6C, 0x69, 0x65 } });

		// Create the memory scan thread
		Utils::Threads::GetThreadPool()->CreateThread(0xDEAD, Dynsec::Routines::MemoryScanRoutine, nullptr);

		// Close this thread (tmp)
		Utils::Threads::GetThreadPool()->CloseThread(0xBEEF);
	}
}