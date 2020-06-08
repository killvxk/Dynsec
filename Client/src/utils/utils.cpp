#include "utils.hpp"
#include <algorithm>
#include "utils/secure/syscall.hpp"
#include "utils/secure/virtual.hpp"
#include "utils/structs.hpp"
#include "utils/secure/module.hpp"

namespace Utils {
	std::string CreateRandomString(int length) {
		auto randchar = [] () -> char {
			const char Charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
			return Charset[rand() % (sizeof(Charset) - 1)];
		};

		std::string str(length, 0);
		std::generate_n(str.begin(), length, randchar);
		return str;
	}

	std::vector<uint8_t> ConvertNumberToBytes(uint32_t param) {
		std::vector<uint8_t> arrayOfByte(4);
		for (uint8_t i = 0; i < 4; i++)
			arrayOfByte[3 - i] = (param >> (i * 8));
		return arrayOfByte;
	}
	uint64_t GetThreadEntryPoint(HANDLE hThread)
	{
		NTSTATUS ntStatus;
		DWORD64 dwThreadStartAddr = 0;
		HANDLE hNewThreadHandle;

		if (DuplicateHandle(GetCurrentProcess(), hThread, GetCurrentProcess(), &hNewThreadHandle, THREAD_QUERY_INFORMATION, FALSE, 0)) {
			ntStatus = Utils::Secure::GetSyscalls()->NtQueryInformationThread(hNewThreadHandle, /*ThreadQuerySetWin32StartAddress*/9, &dwThreadStartAddr, sizeof(DWORD64), NULL);
			CloseHandle(hNewThreadHandle);
			if (ntStatus > 0) return 0;
		}

		return dwThreadStartAddr;
	}
}