#pragma once
#include "stdafx.hpp"

namespace Dynsec::Crypto {
	void RC4(uint8_t* pbKey, uint32_t cbKey, uint8_t* pbInpOut, uint32_t cbInpOut, uint32_t Offset = 0);
}