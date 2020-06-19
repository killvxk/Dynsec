#pragma once
#include "stdafx.hpp"

namespace Dynsec::RoutineTypes {
	struct MemorySignature {
		uint16_t m_Identifier;							// Identifier sent back to our server for reporting
		bool m_Executable;								// If the signature is for executable only memory
		std::string m_Signature;						// The signature itself
	};

	struct ThreadEntrySignature {
		uint16_t m_Identifier;							// Identifier sent back to our server for reporting
		std::string m_Signature;						// The signature itself
	};

	struct WindowInfo {
		std::string m_Name;								// The title of the window
		LONG m_Style;									// The window style
		LONG m_ExtendedStyle;							// The window extended style
		bool m_CurrentProcess;							// If it belongs to the current process
	};
}