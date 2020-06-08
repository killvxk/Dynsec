#pragma once
#include "stdafx.hpp"
#include "dynsec/types/packet_types.hpp"

namespace Dynsec::Network {
	void EncryptPacket(Dynsec::PacketTypes::Request::NetworkBaseHeader* Header);
	void DecryptPacket(Dynsec::PacketTypes::Request::NetworkBaseHeader* Header, Dynsec::PacketTypes::Response::EncryptionKeys* ResponseEncryptionKeys, uint8_t* Bytes, uint32_t Size);
}