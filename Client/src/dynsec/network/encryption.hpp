#pragma once
#include "stdafx.hpp"
#include "dynsec/types/packet_types.hpp"

namespace Dynsec::Network {
	void EncryptPacket(Dynsec::PacketTypes::Request::NetworkBaseHeader* Header);
}