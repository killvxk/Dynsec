#pragma once
#include "stdafx.hpp"

namespace Dynsec::Shellcode {
	struct ShellcodeContext {
		uint64_t m_Sleep;
		uint64_t m_Malloc;
		uint64_t m_Free;
	};

	void Execute(void* Shellcode);
}