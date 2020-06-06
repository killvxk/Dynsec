#include "shellcode.hpp"
#include "utils/caller.hpp"
#include <future>

namespace Dynsec::Shellcode {
	void Execute(void* Shellcode) {
		ShellcodeContext* Context = new ShellcodeContext();
		// ... setup context

		if (Shellcode) {
			std::async(std::launch::deferred, [&] {
				Utils::Caller::Call<int>((uint64_t)Shellcode, Context);
			}).wait();
		}

		delete Context;
	}
}