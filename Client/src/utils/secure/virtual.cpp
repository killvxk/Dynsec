#include "virtual.hpp"
#include "syscall.hpp"
#include "utils/caller.hpp"

namespace Utils::Secure {
	LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
		LPVOID Address = lpAddress;
		if (GetSyscalls()->NtAllocateVirtualMemory(GetCurrentProcess(), &Address, 0, &dwSize, flAllocationType, flProtect) >= 0) {
			return Address;
		}

		return nullptr;
	}

	BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
		if (dwFreeType & 0xFFFF3FFC || (dwFreeType & 0x8003) == 0x8000 && dwSize) {
			return FALSE;
		}

		NTSTATUS Status = GetSyscalls()->NtFreeVirtualMemory(GetCurrentProcess(), &lpAddress, &dwSize, dwFreeType);
		if (Status == 0xC0000045) {
			// NEEDED:
			/*if (!RtlFlushSecureMemoryCache(lpAddress, dwSize)) {
				return FALSE;
			}*/

			Status = GetSyscalls()->NtFreeVirtualMemory(GetCurrentProcess(), &lpAddress, &dwSize, dwFreeType);
			if (Status >= 0) {
				return TRUE;
			}
		}

		return FALSE;
	}

	BOOL VirtualProtect(LPVOID lpAddress, ULONG dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
		NTSTATUS Status = GetSyscalls()->NtProtectVirtualMemory(GetCurrentProcess(), &lpAddress, &dwSize, flNewProtect, lpflOldProtect);
		if (Status >= 0 || Status == 0xC0000045
			// NEEDED:
			// && RtlFlushSecureMemoryCache(lpAddress, dwSize)
			&& GetSyscalls()->NtProtectVirtualMemory(GetCurrentProcess(), &lpAddress, &dwSize, flNewProtect, lpflOldProtect) >= 0) {
			return TRUE;
		}

		return FALSE;
	}
}