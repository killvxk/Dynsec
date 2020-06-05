#pragma once
#include "stdafx.hpp"

namespace Math {
	template<class T> T __ROL__(T value, int count) {
		const uint64_t nbits = sizeof(T) * 8;

		if (count > 0) {
			count %= nbits;
			T high = value >> (nbits - count);
			if (T(-1) < 0)
				high &= ~((T(-1) << count));
			value <<= count;
			value |= high;
		} else {
			count = -count % nbits;
			T low = value << (nbits - count);
			value >>= count;
			value |= low;
		}
		return value;
	}

	inline uint8_t __ROL1__(uint8_t value, int count) { return __ROL__(value, count); }
	inline uint8_t __ROR1__(uint8_t value, int count) { return __ROL__(value, -count); }

	inline uint16_t __ROL2__(uint16_t value, int count) { return __ROL__(value, count); }
	inline uint16_t __ROR2__(uint16_t value, int count) { return __ROL__(value, -count); }

	inline uint32_t __ROL4__(uint32_t value, int count) { return __ROL__(value, count); }
	inline uint32_t __ROR4__(uint32_t value, int count) { return __ROL__(value, -count); }

	inline uint64_t __ROL8__(uint64_t value, int count) { return __ROL__(value, count); }
	inline uint64_t __ROR8__(uint64_t value, int count) { return __ROL__(value, -count); }
}