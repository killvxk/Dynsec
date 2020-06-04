#include "syscall.hpp"

namespace Utils::Secure {


	Syscalls* GetSyscalls() {
		static Syscalls instance;
		return &instance;
	}
}