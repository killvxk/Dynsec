#include "encryption.hpp"
#include "dynsec/crypto/crypto.hpp"
#include "utils/utils.hpp"

namespace Dynsec::Network {
	void EncryptPacket(Dynsec::PacketTypes::Request::NetworkBaseHeader* Header) {
		uint32_t NetworkBaseHeaderSize = sizeof(Dynsec::PacketTypes::Request::NetworkBaseHeader);

		// First, encrypt the session token
		Dynsec::Crypto::RC4(Header->m_Encryption.m_SessionTokenKey, sizeof(Header->m_Encryption.m_SessionTokenKey), Header->m_SessionToken, sizeof(Header->m_SessionToken));

		// Next, RC4 the body with the generated HMAC sha1 hash of the body's content (PRE ENCRYPTION)
		Dynsec::Crypto::RC4(Header->m_RequestHMAC, sizeof(Header->m_RequestHMAC), (uint8_t*)Header, Header->m_Size, NetworkBaseHeaderSize);

		// Next, XOR using the first XOR key, and NOT the result
		BYTE* ByteArr = (BYTE*)(Header + NetworkBaseHeaderSize);
		for (uint32_t i = 0; i < Header->m_Size; i++) {
			ByteArr[i] ^= Header->m_Encryption.m_FirstXorKey;
			ByteArr[i] = ~ByteArr[i];
		}

		// Finally, RC4 the result
		Dynsec::Crypto::RC4(Header->m_Encryption.m_FinalKey, sizeof(Header->m_Encryption.m_FinalKey), (uint8_t*)Header, Header->m_Size, NetworkBaseHeaderSize);
	}

	void DecryptPacket(Dynsec::PacketTypes::Request::NetworkBaseHeader* Header, Dynsec::PacketTypes::Response::EncryptionKeys* ResponseEncryptionKeys, uint8_t* Bytes, uint32_t Size) {
		// First, RC4 the response with the key used in the request
		Dynsec::Crypto::RC4(Header->m_Encryption.m_FinalKey, sizeof(Header->m_Encryption.m_FinalKey), Bytes, Size);

		// Store the xor keys on the stack
		uint16_t XorKeys[] = {
			0x1234, 0x1723, 0x1823, 0x3481,
			0x8312, 0x1212, 0x4782, 0x3484,
			0x1284, 0x7334, 0x8473, 0x8333,
			0x1244, 0x4747, 0x7733, 0x8334
		};

		// Decrypt the first key
		for (uint8_t i = 0; i < 0x10; i++) {
			ResponseEncryptionKeys->m_Key1[i] ^= 0x1337;
			ResponseEncryptionKeys->m_Key1[i] ^= XorKeys[i];
			ResponseEncryptionKeys->m_Key1[i] = ~ResponseEncryptionKeys->m_Key1[i];
		}

		// Decrypt the second key
		for (uint8_t i = 0; i < 0x10; i++) {
			ResponseEncryptionKeys->m_Key2[i] = ~ResponseEncryptionKeys->m_Key2[i];
			ResponseEncryptionKeys->m_Key2[i] ^= 0x1337;
			ResponseEncryptionKeys->m_Key2[i] ^= XorKeys[0x10 - i - 1];
		}

		// Decrypt the hash using the decrypted keys
		for (uint8_t i = 0; i < 0x10; i++) {
			ResponseEncryptionKeys->m_Hash ^= (ResponseEncryptionKeys->m_Key1[i] ^ ResponseEncryptionKeys->m_Key2[i]);
			ResponseEncryptionKeys->m_Hash ^= ResponseEncryptionKeys->m_Key2[i];
			ResponseEncryptionKeys->m_Hash ^= ResponseEncryptionKeys->m_Key1[i];
			ResponseEncryptionKeys->m_Hash = ~ResponseEncryptionKeys->m_Hash;
		}

		// Convert the decrypted hash to bytes
		auto HashBytes = Utils::ConvertNumberToBytes(ResponseEncryptionKeys->m_Hash);

		// Use said bytes
		for (uint32_t i = 0; i < Size; i++) {
			Bytes[i] ^= HashBytes[3];
			Bytes[i] = ~Bytes[i];
			Bytes[i] ^= HashBytes[2];
			Bytes[i] = ~Bytes[i];
			Bytes[i] ^= HashBytes[1];
			Bytes[i] = ~Bytes[i];
			Bytes[i] ^= HashBytes[0];
		}

		// Finally, RC4 the end result with the session token key
		Dynsec::Crypto::RC4(Header->m_Encryption.m_SessionTokenKey, sizeof(Header->m_Encryption.m_SessionTokenKey), Bytes, Size);
	}
}