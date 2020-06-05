#include "network_socket.hpp"

namespace Dynsec::Network {
	bool TCP::Initialize() {
		static bool IsInitialized = false;
		if (IsInitialized) return true;

		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData)) return false;

		return IsInitialized = true;
	}

	TCP& TCP::Create(NetworkStatus& Status) {
		if (!Initialize()) {
			Status.m_Successful = false;
			Status.m_Error = "Failed to initialize socket";
			return *this;
		}

		bool IsSocketCreated = false;

		for (int i = 0; i < MAX_SOCKET_CREATE_RETRIES; i++) {
			SocketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (SocketHandle == SOCKET_ERROR) {
				IsSocketCreated = false;
				printf("Failed to create socket, attempt %i\n", i + 1);
			} else {
				IsSocketCreated = true;
				break;
			}

			Sleep(250);
		}

		if (!IsSocketCreated) {
			Status.m_Successful = false;
			Status.m_Error = "Socket wasn't created";
			return *this;
		}

		Status.m_Successful = true;
		return *this;
	}

	TCP& TCP::Connect(NetworkStatus& Status) {
#undef max
		int SendRecvSize = std::numeric_limits<int>::max();
		setsockopt(SocketHandle, SOL_SOCKET, SO_SNDBUF | SO_RCVBUF, (const char*)&SendRecvSize, sizeof(SendRecvSize));

		int MaxTimeout = SOCKET_TIMEOUT;
		setsockopt(SocketHandle, SOL_SOCKET, SO_SNDTIMEO | SO_RCVTIMEO, (const char*)&MaxTimeout, sizeof(MaxTimeout));

		Dynsec::PacketTypes::GameServer Server(ACTIVE_CLIENT);

		sockaddr_in SocketAddress;
		SocketAddress.sin_family = AF_INET;
		SocketAddress.sin_port = htons(Server.m_Port);
		SocketAddress.sin_addr.S_un.S_addr = htonl(Server.m_IP);

		bool IsConnected = false;

		for (int i = 0; i < MAX_SOCKET_CONNECT_RETRIES; i++) {
			if (connect(SocketHandle, (sockaddr*)&SocketAddress, sizeof(SocketAddress)) == SOCKET_ERROR) {
				IsConnected = false;
				printf("Failed to connect, attempt %i\n", i + 1);
			} else {
				IsConnected = true;
				break;
			}

			Sleep(250);
		}

		if (!IsConnected) {
			closesocket(SocketHandle);
			Status.m_Successful = false;
			Status.m_Error = "Failed to connect";
			return *this;
		}

		Status.m_Successful = true;
		return *this;
	}

	TCP& TCP::Send(void* Buffer, uint32_t Size, NetworkStatus& Status) {
		uint32_t RemainingSize = Size;
		uint32_t SentSize = 0;

		while (RemainingSize > 0) {
			uint32_t SendingSize = min(RemainingSize, 0x1000);
			int Sent = send(SocketHandle, (const char*)Buffer + SentSize, SendingSize, 0);
			
			if (Sent == SOCKET_ERROR) {
				Status.m_Successful = false;
				Status.m_Error = "Failed to send";
				return *this;
			}

			RemainingSize -= Sent;
			SentSize += Sent;
		}

		Status.m_Successful = true;
		return *this;
	}

	TCP& TCP::Receive(Dynsec::PacketTypes::Request::NetworkBaseHeader* Header, void* RecvBuffer, uint32_t RecvSize, NetworkStatus& Status) {
		char* ReceivedBuffer = new char[RecvSize];

		uint32_t RemainingSize = RecvSize;
		uint32_t ReceivedSize = 0;

		while (RemainingSize > 0) {
			uint32_t ReceivingSize = min(RemainingSize, 0x1000);
			uint32_t Received = (uint32_t)recv(SocketHandle, ReceivedBuffer + ReceivedSize, ReceivingSize, 0);
			printf("Received %i bytes\n", Received);

			if (Received == SOCKET_ERROR) {
				Status.m_Successful = false;
				Status.m_Error = "Failed to receive";
				closesocket(SocketHandle);
				return *this;
			}

			if (Received == 0) break;

			RemainingSize -= Received;
			ReceivedSize += Received;
		}

		Status.m_ReadBytes = ReceivedSize;
		Status.m_Successful = true;
		closesocket(SocketHandle);

		// handle decryption shit here

		// temp
		memcpy(RecvBuffer, ReceivedBuffer, ReceivedSize);

		delete[] ReceivedBuffer;
		return *this;
	}
}