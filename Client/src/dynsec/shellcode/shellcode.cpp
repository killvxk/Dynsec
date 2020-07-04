#include "shellcode.hpp"
#include "utils/caller.hpp"
#include <future>

namespace Dynsec::Shellcode {
	ShellcodeContext* SetupContext() {
		ShellcodeContext* Context = new ShellcodeContext();

		if (Context) {
			Context->m_Sleep = (uint64_t)&Sleep;
			Context->m_Malloc = (uint64_t)&malloc;
			Context->m_Free = (uint64_t)&free;
		}

		return Context;
	}

	void Execute(void* Shellcode) {
		if (Shellcode) {
			// SHELLCODE SHOULD DELETE CONTEXT
			ShellcodeContext* Context = SetupContext();

			auto f = std::async(std::launch::async, [&] {
				Utils::Caller::Call<int>((uint64_t)Shellcode, Context);
			});
		}
	}
}