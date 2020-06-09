#pragma once
#include "stdafx.hpp"

namespace Utils::Secure {
	LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
	BOOL VirtualProtect(LPVOID lpAddress, ULONG dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	BOOL ReadProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesRead);
	HANDLE CreateThread(SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

	std::vector<MEMORY_BASIC_INFORMATION> GetMemoryPages();
}