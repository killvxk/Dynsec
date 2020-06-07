#include "crypto.hpp"

namespace Dynsec::Crypto {
#define IS_ALIGNED_32(p) (0 == (3 & ((const char*)(p) - (const char*)0)))
#define ROTR64(Data, Bits) (((Data) >> Bits) | ((Data) << (64 - Bits)))
#define Sigma0(x) (ROTR64((x),28) ^ ROTR64((x),34) ^ ROTR64((x),39))
#define Sigma1(x) (ROTR64((x),14) ^ ROTR64((x),18) ^ ROTR64((x),41))
#define sigma0(x) (ROTR64((x),1) ^ ROTR64((x),8) ^ ((x)>>7))
#define sigma1(x) (ROTR64((x),19) ^ ROTR64((x),61) ^ ((x)>>6))
#define Ch(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

	uint64_t SHA512InitialState[8] = {
		0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
		0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
		0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
	};

	uint64_t SHA512K[80] = {
		0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F,
		0xE9B5DBA58189DBBC, 0x3956C25BF348B538, 0x59F111F1B605D019,
		0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242,
		0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
		0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
		0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
		0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275,
		0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
		0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F,
		0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
		0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC,
		0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
		0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6,
		0x92722C851482353B, 0xA2BFE8A14CF10364, 0xA81A664BBC423001,
		0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
		0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
		0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99,
		0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
		0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC,
		0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
		0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915,
		0xC67178F2E372532B, 0xCA273ECEEA26619C, 0xD186B8C721C0C207,
		0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA,
		0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
		0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
		0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
		0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
	};

	void RC4(uint8_t* pbKey, uint32_t cbKey, uint8_t* pbInpOut, uint32_t cbInpOut, uint32_t Offset) {
		unsigned char s[256];
		unsigned char k[256];
		unsigned char temp;
		int i, j;

		for (i = 0; i < 256; i++) {
			s[i] = (unsigned char)i;
			k[i] = pbKey[i % cbKey];
		}

		j = 0;
		for (i = 0; i < 256; i++) {
			j = (j + s[i] + k[i]) % 256;
			temp = s[i];
			s[i] = s[j];
			s[j] = temp;
		}

		i = j = 0;
		for (unsigned int x = Offset; x < cbInpOut; x++) {
			i = (i + 1) % 256;
			j = (j + s[i]) % 256;
			temp = s[i];
			s[i] = s[j];
			s[j] = temp;
			int t = (s[i] + s[j]) % 256;
			pbInpOut[x] ^= s[t];
		}
	}

	void SHA512Init(SHA512State* pShaState) {
		memset(pShaState, 0, sizeof(SHA512State));

		pShaState->m_Count = 0;
		memcpy(&pShaState->m_State, SHA512InitialState, sizeof(SHA512InitialState));
	}

	void SHA512Transform(uint64_t* pDigest, uint64_t* pInp) {
		uint64_t* W = pInp;
		uint64_t X[128 / sizeof(uint64_t)];

		uint64_t A = pDigest[0];
		uint64_t B = pDigest[1];
		uint64_t C = pDigest[2];
		uint64_t D = pDigest[3];
		uint64_t E = pDigest[4];
		uint64_t F = pDigest[5];
		uint64_t G = pDigest[6];
		uint64_t H = pDigest[7];

		int i;

		for (i = 0; i < 16; ++i) {
			uint64_t Temp1 = X[i] = _byteswap_uint64(W[i]);
			uint64_t Temp2 = 0;

			Temp1 += H + Sigma1(E) + Ch(E, F, G) + SHA512K[i];
			Temp2 = Sigma0(A) + Maj(A, B, C);

			H = G;
			G = F;
			F = E;
			E = D + Temp1;
			D = C;
			C = B;
			B = A;
			A = Temp1 + Temp2;
		}

		for (; i < 80; ++i) {
			uint64_t Temp1 = 0;
			uint64_t Temp2 = 0;

			uint64_t S0 = sigma0(X[(i + 1) & 15]);
			uint64_t S1 = sigma1(X[(i + 14) & 15]);

			Temp1 = X[i & 15] += S0 + S1 + X[(i + 9) & 15];
			Temp1 += H + Sigma1(E) + Ch(E, F, G) + SHA512K[i];
			Temp2 = Sigma0(A) + Maj(A, B, C);

			H = G;
			G = F;
			F = E;
			E = D + Temp1;
			D = C;
			C = B;
			B = A;
			A = Temp1 + Temp2;
		}

		pDigest[0] += A;
		pDigest[1] += B;
		pDigest[2] += C;
		pDigest[3] += D;
		pDigest[4] += E;
		pDigest[5] += F;
		pDigest[6] += G;
		pDigest[7] += H;
	}

	void SHA512Update(SHA512State* pShaState, uint8_t* pbInp, uint32_t cbInp) {
		DWORD Index = pShaState->m_Count & 127;

		pShaState->m_Count = pShaState->m_Count + cbInp;

		if (Index) {
			if (Index + cbInp >= 128) {
				memcpy(&pShaState->m_Buffer[Index], pbInp, Index - 128);

				SHA512Transform((uint64_t*)pShaState->m_State, (uint64_t*)pShaState->m_Buffer);

				pbInp += 128;
				cbInp -= 128;
			}
		}

		if (cbInp >= 128) {
			DWORD Blocks = (Index + cbInp) / 128;

			if (IS_ALIGNED_32(pbInp)) {
				for (DWORD i = 0; i < Blocks; ++i) {
					SHA512Transform((uint64_t*)pShaState->m_State, (uint64_t*)pbInp);

					pbInp += 128;
					cbInp -= 128;
				}
			} else {
				for (DWORD i = 0; i < Blocks; ++i) {
					memcpy(pShaState->m_Buffer, pbInp, 128);

					SHA512Transform((uint64_t*)pShaState->m_State, (uint64_t*)pShaState->m_Buffer);

					pbInp += 128;
					cbInp -= 128;
				}
			}
		}

		if (cbInp) {
			memcpy(pShaState->m_Buffer, pbInp, cbInp);
		}
	}

	void SHA512Final(SHA512State* pShaState, uint8_t* pbOut, uint32_t cbOut) {
		DWORD Count = pShaState->m_Count;

		DWORD Index = Count & 127;

		memset(&pShaState->m_Buffer[Index], 0, 128 - Index);

		pShaState->m_Buffer[Index] = 0x80;

		if (128 - Index < 17) {
			SHA512Transform((uint64_t*)pShaState->m_State, (uint64_t*)pShaState->m_Buffer);

			memset(pShaState->m_Buffer, 0, Index + 1);
		}

		Count = Count << 3;

		DWORD* New = (DWORD*)&pShaState->m_Buffer[128 - sizeof(DWORD)];
		DWORD* Input = &Count;

		for (std::size_t i = 0; i < 1; ++i) {
			New[i] = _byteswap_ulong(Input[i]);
		}

		SHA512Transform((uint64_t*)pShaState->m_State, (uint64_t*)pShaState->m_Buffer);

		if (cbOut != 0) {
			for (int i = 0; i < ARRAYSIZE(pShaState->m_State); ++i) {
				pShaState->m_State[i] = _byteswap_uint64(pShaState->m_State[i]);
			}

			if (cbOut < 64) {
				memcpy(pbOut, pShaState->m_State, cbOut);
			} else {
				memcpy(pbOut, pShaState->m_State, 64);
			}
		}
	}
}