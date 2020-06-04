#pragma once
#include "stdafx.hpp"

namespace Utils::Secure {
#undef GetModuleHandle

	HMODULE GetModuleHandle(const wchar_t* moduleName);
	FARPROC GetProcAddress(HMODULE moduleHandle, const char* procName, bool disk = false);
}