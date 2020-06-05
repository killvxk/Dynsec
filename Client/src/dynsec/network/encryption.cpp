#include "encryption.hpp"
#include "dynsec/crypto/rc4.hpp"

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
}