#pragma once
#include "stdafx.hpp"

namespace Utils {
	std::string CreateRandomString(int length);
	std::string ConvertBytesToString(uint8_t* data, uint32_t length, bool space = false);
	std::vector<uint8_t> ConvertNumberToBytes(uint32_t param);
	uint64_t GetThreadEntryPoint(HANDLE hThread);
	void ReplaceString(std::string& str, std::string from, std::string to);
}