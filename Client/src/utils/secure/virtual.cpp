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

	HANDLE CreateThread(SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
		// Will not behave exactly like CreateThread, there's actually quite a bit of setup done CreateThread before calling the nt func
		HANDLE hThread = 0;
		DWORD v10 = dwCreationFlags & 0x10000;

		struct {
			DWORD pid;
			DWORD _pad1;
			DWORD tid;
			DWORD _pad2;
		} newThreadInfo;

		DWORD64 unkData = 0;

		DWORD64 unkThreadInfo[9];
		unkThreadInfo[0] = 32 * 2 + 8; // from KernelBase.CreateThreadEx. (also size of unkThreadInfo)
		unkThreadInfo[1] = 0x10003;
		unkThreadInfo[2] = 0x10;
		unkThreadInfo[4] = 0;
		unkThreadInfo[3] = (__int64)&newThreadInfo;
		unkThreadInfo[5] = 0x10004;
		unkThreadInfo[6] = 8;
		unkThreadInfo[8] = 0;
		unkThreadInfo[7] = (__int64)&unkData;

		NTSTATUS Status = GetSyscalls()->NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, (HANDLE)-1, lpStartAddress, lpParameter, FALSE, NULL, NULL, dwStackSize & -(signed __int64)(v10 != 0), &unkThreadInfo[0]);
		
		if (lpThreadId)
			*lpThreadId = newThreadInfo.tid;
		
		if (!(dwCreationFlags & CREATE_SUSPENDED))
			ResumeThread(hThread); // TODO: syscall NtResumeThread

		if (Status >= 0)
			return hThread;
		return (HANDLE)INVALID_HANDLE_VALUE; 
	}
}