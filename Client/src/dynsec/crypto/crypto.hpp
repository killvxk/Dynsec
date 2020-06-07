#pragma once
#include "stdafx.hpp"

namespace Dynsec::Crypto {
	struct SHA512State {
		uint32_t m_Count;
		uint64_t m_State[8];
		uint8_t m_Buffer[128];
	};

	void RC4(uint8_t* pbKey, uint32_t cbKey, uint8_t* pbInpOut, uint32_t cbInpOut, uint32_t Offset = 0);
	void SHA512Init(SHA512State* pShaState);
	void SHA512Update(SHA512State* pShaState, uint8_t* pbInp, uint32_t cbInp);
	void SHA512Final(SHA512State* pShaState, uint8_t* pbOut, uint32_t cbOut);
}