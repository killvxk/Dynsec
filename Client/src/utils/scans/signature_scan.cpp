#include "signature_scan.hpp"
#include "utils/secure/syscall.hpp"
#include <sstream>

namespace Utils::Scans {
	struct PatternByte {
		PatternByte()
			: m_Ignore(true), m_Data(0)
		{};

		PatternByte(const char* Pattern, bool Ignore = false)
			: m_Data(ConvertString(Pattern)), m_Ignore(Ignore)
		{}

		bool m_Ignore;
		uint8_t m_Data;
	private:
		uint8_t ConvertString(const char* Pattern) {
			std::istringstream StringStream(Pattern);
			uint32_t Return = 0;

			if (StringStream >> std::hex >> Return) {
				return (uint8_t)Return;
			}

			return 0;
		}
	};

	uint64_t PatternScan(uint64_t Start, uint64_t End, const char* Pattern) {
		std::vector<PatternByte> PatternBytes;
		std::istringstream StringStream(Pattern);
		std::string CurrentByte = "";

		// Prevent somehow spoofing patterns to be extremely long to slow down scanning
		if (Pattern && strlen(Pattern) < 0x200) {
			while (StringStream >> CurrentByte) {
				if (CurrentByte.data()[0] == '?') {
					PatternBytes.push_back(PatternByte());
				} else if (CurrentByte.length() == 2 && isxdigit(CurrentByte.data()[0]) && isxdigit(CurrentByte.data()[1])) { // Hex
					PatternBytes.push_back(PatternByte(CurrentByte.c_str()));
				} else {
					return 0;
				}
			}

			for (uint64_t i = Start; i < End; i++) {
				uint8_t* Current = (uint8_t*)i;
				bool Found = true;

				for (std::size_t ps = 0; ps < PatternBytes.size(); ps++) {
					if (!PatternBytes[ps].m_Ignore && Current[ps] != PatternBytes[ps].m_Data) {
						Found = false;
						break;
					}
				}

				if (Found) {
					return (uint64_t)Current;
				}
			}
		}

		return 0;
	}

	uint64_t PatternScanExternalProcess(HANDLE Process, uint64_t Start, uint64_t End, const char* Pattern) {
		uint8_t* ProcessBytes = new uint8_t[End - Start];
		memset(ProcessBytes, 0, End - Start);

		ULONG ReadSize = 0;
		if (Utils::Secure::GetSyscalls()->NtReadVirtualMemory(Process, (void*)Start, ProcessBytes, (ULONG)(End - Start), &ReadSize) == 0) {
			uint64_t Return = PatternScan((uint64_t)ProcessBytes, ((uint64_t)ProcessBytes + (End - Start)), Pattern);
			if (Return) {
				Return = (Return - (uint64_t)ProcessBytes) + Start; // Get the offset in the real process where it is
			}

			delete[] ProcessBytes;
			return Return;
		}

		delete[] ProcessBytes;
		return 0;
	}
}