#pragma once
#include "stdafx.hpp"

namespace Dynsec::RoutineTypes {
	struct MemorySignature {
		uint16_t m_Identifier;							// Identifier sent back to our server for reporting
		bool m_Executable;								// If the signature is for executable only memory
		std::string m_Signature;						// The signature itself
	};
}