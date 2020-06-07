#include "utils.hpp"
#include <algorithm>

namespace Utils {
	std::string CreateRandomString(int length) {
		auto randchar = [] () -> char {
			const char Charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
			return Charset[rand() % (sizeof(Charset) - 1)];
		};

		std::string str(length, 0);
		std::generate_n(str.begin(), length, randchar);
		return str;
	}

	std::vector<uint8_t> ConvertNumberToBytes(uint32_t param) {
		std::vector<uint8_t> arrayOfByte(4);
		for (uint8_t i = 0; i < 4; i++)
			arrayOfByte[3 - i] = (param >> (i * 8));
		return arrayOfByte;
	}
}