#include "pointers.hpp"
#include "utils/math.hpp"
#include "syscall.hpp"

namespace Utils::Secure {
	void* Pointers::EncodePointer(void* Ptr) {
		if (!m_Cookie) {
			ULONG ReturnLength = 0;
			if (GetSyscalls()->NtQueryInformationProcess(GetCurrentProcess(), 0x24, &m_Cookie, 4, &ReturnLength) != 0) {
				return nullptr;
			}
		}

		uint64_t Address = (uint64_t)Ptr;
		Address = Math::__ROL8__(Address, 2);
		Address = Math::__ROL8__(Address, 0x20);
		Address = ~Address;
		for (uint32_t i = 0; i < (m_Cookie & 0x3F); i++) Address = (Address ^ m_Cookie) ^ i;

		return (void*)Address;
	}

	void* Pointers::DecodePointer(void* Ptr) {
		if (!m_Cookie) {
			ULONG ReturnLength = 0;
			if (GetSyscalls()->NtQueryInformationProcess(GetCurrentProcess(), 0x24, &m_Cookie, 4, &ReturnLength) != 0) {
				return nullptr;
			}

			printf("m_Cookie: %x\n", m_Cookie);
		}

		uint64_t Address = (uint64_t)Ptr;
		for (uint32_t i = 0; i < (m_Cookie & 0x3F); i++) Address = (Address ^ m_Cookie) ^ i;
		Address = ~Address;
		Address = Math::__ROL8__(Address, 0x20);
		Address = Math::__ROL8__(Address, 2);

		return (void*)(Address >> 4);
	}

	Pointers* GetPointers() {
		static Pointers Instance;
		return &Instance;
	}
}