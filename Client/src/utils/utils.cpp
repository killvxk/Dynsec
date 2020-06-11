#include "utils.hpp"
#include <algorithm>
#include "utils/secure/syscall.hpp"
#include "utils/secure/virtual.hpp"
#include "utils/structs.hpp"
#include "utils/secure/module.hpp"
#include "dynsec/crypto/crypto.hpp"
#include <sstream>
#include <iomanip>

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

	std::string ConvertBytesToString(uint8_t* data, uint32_t length, bool space) {
		std::stringstream str;
		str.setf(std::ios_base::hex, std::ios::basefield);
		str.setf(std::ios_base::uppercase);
		str.fill('0');

		for (uint32_t i = 0; i < length; ++i) {
			str << std::setw(2) << (unsigned short)data[i];

			if (space && i != length - 1) {
				str << " ";
			}
		}

		return str.str();
	}

	std::vector<uint8_t> ConvertNumberToBytes(uint32_t param) {
		std::vector<uint8_t> arrayOfByte(4);
		for (uint8_t i = 0; i < 4; i++)
			arrayOfByte[3 - i] = (param >> (i * 8));
		return arrayOfByte;
	}

	uint64_t GetThreadEntryPoint(HANDLE hThread) {
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

	void ReplaceString(std::string& str, std::string from, std::string to) {
		size_t start_pos = 0;
		while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
			size_t end_pos = start_pos + from.length();
			while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
				str.replace(start_pos, from.length(), to);
				start_pos += to.length(); // ...
			}
			start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
		}
	}
}