#pragma once
#include "stdafx.hpp"

namespace Utils::Module {
#undef GetModuleHandle

	HMODULE GetModuleHandle(const wchar_t* moduleName);
	FARPROC GetProcAddress(HMODULE moduleHandle, const char* procName);
}