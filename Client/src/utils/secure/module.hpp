#pragma once
#include "stdafx.hpp"

namespace Utils::Secure {
#undef GetModuleHandle

	HMODULE GetModuleHandle(const wchar_t* moduleName);
	FARPROC GetProcAddressDisk(HMODULE hMod, const char* procName);
	FARPROC GetProcAddress(HMODULE moduleHandle, const char* procName);
}