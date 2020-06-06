#pragma once
#include "stdafx.hpp"

namespace Dynsec::Shellcode {
	struct ShellcodeContext {
		// give access to winapi & dynsec functions
	};

	void Execute(void* Shellcode);
}