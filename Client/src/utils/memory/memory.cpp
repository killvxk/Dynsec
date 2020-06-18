#include "memory.hpp"

namespace Utils::Memory {
	uint64_t GetAddressFromInstruction(uint64_t Address, uint32_t OpcodeSize, uint32_t OpcodeLength) {
		return (uint64_t)(*(uint32_t*)(Address + OpcodeSize) + Address + OpcodeLength);
	}
}