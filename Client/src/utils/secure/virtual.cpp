#include "virtual.hpp"
#include "syscall.hpp"
#include "utils/caller.hpp"
#include "utils/structs.hpp"
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
			// TODO:
			/*if (!RtlFlushSecureMemoryCache(lpAddress, dwSize)) {
				return FALSE;
			}*/

			Status = GetSyscalls()->NtFreeVirtualMemory(GetCurrentProcess(), &lpAddress, &dwSize, dwFreeType);
		}

		if (Status >= 0) {
			return TRUE;
		}

		return FALSE;
	}

	BOOL VirtualProtect(LPVOID lpAddress, ULONG dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
		NTSTATUS Status = GetSyscalls()->NtProtectVirtualMemory(GetCurrentProcess(), &lpAddress, &dwSize, flNewProtect, lpflOldProtect);
		if (Status >= 0) {
			return TRUE;
		}

		// TODO:
		// && RtlFlushSecureMemoryCache(lpAddress, dwSize)
		if (Status == 0xC0000045) {
			Status = GetSyscalls()->NtProtectVirtualMemory(GetCurrentProcess(), &lpAddress, &dwSize, flNewProtect, lpflOldProtect);
			if ((Status & 0x80000000) == 0) {
				return TRUE;
			}
		}

		return FALSE;
	}

	HANDLE CreateThread(SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
		// Will not behave exactly like CreateThread, there's actually quite a bit of setup done CreateThread before calling the nt func
		HANDLE hThread = 0;

		CLIENT_ID threadClient;
		PTEB pTeb = 0;

		struct {
			uint64_t size;
			uint64_t unk1;
			uint64_t unk2;
			PCLIENT_ID pNewThreadInfo;
			uint64_t unk4;
			uint64_t unk5;
			uint64_t unk6;
			PTEB* ppTEB;
			uint64_t unk8;
		} threadData;

		threadData.size = 32 * 2 + 8; // from KernelBase.CreateThreadEx. (also size of unkThreadInfo)
		threadData.unk1 = 0x10003;
		threadData.unk2 = 0x10;
		threadData.unk4 = 0;
		threadData.pNewThreadInfo = &threadClient;
		threadData.unk5 = 0x10004;
		threadData.unk6 = 8;
		threadData.unk8 = 0;
		threadData.ppTEB = &pTeb;

		NTSTATUS Status = GetSyscalls()->NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, GetCurrentProcess(), lpStartAddress, lpParameter, FALSE, NULL, NULL, dwStackSize & -(signed __int64)((dwCreationFlags & 0x10000) != 0), &threadData);
		
		if (lpThreadId) {
			*lpThreadId = (DWORD)threadClient.UniqueThread;
		}
		
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			ResumeThread(hThread); // TODO: syscall NtResumeThread
		}

		if (Status >= 0) {
			return hThread;
		}

		return (HANDLE)INVALID_HANDLE_VALUE; 
	}

	std::vector<MEMORY_BASIC_INFORMATION> GetMemoryPages() {
		std::vector<MEMORY_BASIC_INFORMATION> Pages;

		NTSTATUS Status = 0;
		uint64_t CurrentScanAddress = 0;
		MEMORY_BASIC_INFORMATION PageInformation = { 0 };
		SIZE_T OutLength = 0;

		while ((Status = GetSyscalls()->NtQueryVirtualMemory(GetCurrentProcess(), (void*)CurrentScanAddress, 0, &PageInformation, sizeof(PageInformation), &OutLength)) == 0) {
			Pages.push_back(PageInformation);
			CurrentScanAddress += PageInformation.RegionSize;
			memset(&PageInformation, 0, sizeof(PageInformation));
		}

		return Pages;
	}
}