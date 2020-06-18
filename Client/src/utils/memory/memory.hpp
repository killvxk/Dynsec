#pragma once
#include "stdafx.hpp"
#include "utils/secure/virtual.hpp"

namespace Utils::Memory {
	uint64_t GetAddressFromInstruction(uint64_t Address, uint32_t OpcodeSize = 3, uint32_t OpcodeLength = 7);

	template<typename A, typename V>
	void Write(uint32_t PageProtection, A Address, V Value, uint32_t Size = sizeof(Value)) {
		uint32_t OldProtection = 0;
		Utils::Secure::VirtualProtect((void*)Address, Size, PageProtection, &OldProtection);
		memcpy((void*)Address, &Value, Size);
		Utils::Secure::VirtualProtect((void*)Address, Size, OldProtection, &OldProtection);
	}
}