#include "shellcode.hpp"
#include "utils/caller.hpp"
#include <future>

namespace Dynsec::Shellcode {

	void Execute(void* Shellcode) {
		ShellcodeContext* Context = new ShellcodeContext();
		// ... setup context
		if (Shellcode) {
			auto f = std::async(std::launch::async, [&] {
				Utils::Caller::Call<int>((uint64_t)Shellcode, Context);
			});
		}

		delete Context;
	}
}