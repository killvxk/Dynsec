#pragma once
#include "stdafx.hpp"

namespace Dynsec::RoutineTypes {
	struct MemorySignature {
		uint16_t m_Identifier;							// Identifier sent back to our server for reporting
		std::vector<uint8_t> m_Signature;				// The signature itself
	};
}