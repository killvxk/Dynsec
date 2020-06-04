#include "rc4.hpp"

namespace Dynsec::Crypto {
	struct XECRYPT_RC4_STATE {
		uint8_t S[256];
		uint8_t i;
		uint8_t j;
	};

	void XeCryptRc4(uint8_t* pbKey, uint32_t cbKey, uint8_t* pbInpOut, uint32_t cbInpOut) {
		XECRYPT_RC4_STATE Rc4State;

		for (DWORD i = 0; i < 256; ++i) {
			Rc4State.S[i] = (BYTE)i;
		}

		Rc4State.i = 0;
		Rc4State.j = 0;

		int j = 0;

		for (DWORD i = 0; i < 256; i++) {
			j = (j + Rc4State.S[i] + pbKey[i % cbKey]) % 256;

			BYTE bTemp = Rc4State.S[i];
			Rc4State.S[i] = Rc4State.S[j];
			Rc4State.S[j] = bTemp;
		}

		int i = Rc4State.i;
		j = Rc4State.j;

		for (DWORD n = 0; n < cbInpOut; ++n) {
			j = (((i + 1) % 256) + Rc4State.S[i]) % 256;

			BYTE bTemp = Rc4State.S[i];
			Rc4State.S[i] = Rc4State.S[j];
			Rc4State.S[j] = bTemp;

			pbInpOut[n] = pbInpOut[n] ^ Rc4State.S[(Rc4State.S[i] + Rc4State.S[j]) % 256];
		}

		Rc4State.i = i;
		Rc4State.j = j;
	}
}