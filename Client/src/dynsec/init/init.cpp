#include "init.hpp"
#include "routines/routines.hpp"
#include "tls_manager.hpp"
#include "global/variables.hpp"
#include "utils/secure/syscall.hpp"
#include "utils/secure/virtual.hpp"
#include "utils/threads/thread_pool.hpp"
#include "utils/secure/pointers.hpp"
#include "utils/utils.hpp"
#include "dynsec/crypto/crypto.hpp"

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
		Global::Vars::g_MemorySignatures.push_back({ 0x1, false, "[Game] -> InitializeClie" });

		// Temp add a thread shellcode (ExtremeInjector -> ManualMap)
		Global::Vars::g_ThreadEntrySignatures.push_back({ 0x1, "48 89 4C 24 08 48 89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 33 C9 48 BA ? ? ? ? ? ? ? ? 4C 8D 05 ? ? ? ? 48 B8 ? ? ? ? ? ? ? ? FF D0" });

		// Temp add a window title
		Global::Vars::g_WindowTitleSignatures.push_back("Chrome");

		// Create the memory scan thread
		Utils::Threads::GetThreadPool()->CreateThread(0xDEAD, Dynsec::Routines::MemoryScanRoutine, nullptr);

		// Create the exploitable module scan thread
		Utils::Threads::GetThreadPool()->CreateThread(0xC0DE, Dynsec::Routines::ExploitableModuleScanRoutine, nullptr);

		// Close this thread (tmp)
		Utils::Threads::GetThreadPool()->CloseThread(0xBEEF);
	}
}