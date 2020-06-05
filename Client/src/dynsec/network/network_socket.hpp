#pragma once
#include "stdafx.hpp"
#include "dynsec/types/packet_types.hpp"
#pragma comment(lib, "Ws2_32.lib")

namespace Dynsec::Network {
	// Setup which custom client we're building for
#define CLIENT_TEST1 { 0x7F000001, 1234 } // 123.0.0.1, 1234
#define CLIENT_TEST2 { 0x7F000001, 1235 } // 123.0.0.1, 1235
#define CLIENT_TEST3 { 0x7F000001, 1236 } // 123.0.0.1, 1236
#define ACTIVE_CLIENT CLIENT_TEST2

// networking stuff
#define MAX_SOCKET_CONNECT_RETRIES 10
#define MAX_SOCKET_CREATE_RETRIES 10
#define SOCKET_TIMEOUT 10000

	struct NetworkStatus {
		bool m_Successful;
		const char* m_Error;
		uint32_t m_ReadBytes; // Receive only
	};

	class TCP {
	public:
		static bool Initialize();

		TCP& Create(NetworkStatus& Status);
		TCP& Connect(NetworkStatus& Status);
		TCP& Send(void* Buffer, uint32_t Size, NetworkStatus& Status);
		TCP& Receive(Dynsec::PacketTypes::Request::NetworkBaseHeader* Header, void* RecvBuffer, uint32_t RecvSize, NetworkStatus& Status);
	private:
		sockaddr_in ServerHandle;
		SOCKET SocketHandle;
	};
}