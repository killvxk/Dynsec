#pragma once
#include "stdafx.hpp"

namespace Utils {
	std::string CreateRandomString(int length);
	std::vector<uint8_t> ConvertNumberToBytes(uint32_t param);
}