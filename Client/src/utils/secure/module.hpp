#pragma once
#include "stdafx.hpp"
#include "../structs.hpp"

namespace Utils::Secure {
#define RVA2VA(type, base, rva) (type)((uint64_t)base + rva)
#define VA2RVA(type, base, va) (type)((uint64_t)va - (uint64_t)base)

#undef GetModuleHandle

	HMODULE GetModuleHandle(const wchar_t* moduleName);
	FARPROC GetProcAddressDisk(HMODULE hMod, const char* procName);
	FARPROC GetProcAddress(HMODULE moduleHandle, const char* procName);

	std::vector<PIMAGE_SECTION_HEADER> GetModuleSections(HMODULE hModule);
	std::vector<PLDR_DATA_TABLE_ENTRY> GetMappedModules();
}