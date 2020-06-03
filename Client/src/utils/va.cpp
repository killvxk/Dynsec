#include "va.hpp"

namespace Utils::VA {
	char vaStorage[0x200];
	const char* VA(const char* fmt, ...) {
		memset(vaStorage, 0, 0x200);
		va_list ap;
		va_start(ap, fmt);
		vsprintf_s(vaStorage, fmt, ap);
		va_end(ap);
		return vaStorage;
	}

	const wchar_t* VAW(const char* fmt, ...) {
		CHAR Buffer[0x1000];
		CHAR MessageBuffer[0x100];
		static WCHAR Message[0x100];

		va_list pArgList;
		va_start(pArgList, fmt);
		vsprintf_s(Buffer, fmt, pArgList);
		va_end(pArgList);

		sprintf(MessageBuffer, Buffer);
		mbstowcs(Message, MessageBuffer, strlen(MessageBuffer) + 1);

		ZeroMemory(Buffer, sizeof(Buffer));
		ZeroMemory(MessageBuffer, sizeof(MessageBuffer));

		return Message;
	}

	const char* VABuffer(char* buffer, std::size_t size, const char* fmt, ...) {
		memset(buffer, 0, size);
		va_list ap;
		va_start(ap, fmt);
		vsprintf(buffer, fmt, ap);
		va_end(ap);
		return buffer;
	}
}