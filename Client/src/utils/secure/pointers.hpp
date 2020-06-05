#pragma once
#include "stdafx.hpp"

namespace Utils::Secure {
	class Pointers {
	public:
		void* EncodePointer(void* Ptr);
		void* DecodePointer(void* Ptr);
	private:
		uint32_t m_Cookie;
	};

	Pointers* GetPointers();
}