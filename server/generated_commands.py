CMD_KILL = 1
CMD_INSPECT_TOKEN = 2
CMD_PROCESS_TOKEN = 3
CMD_TOKEN_PRIVILEGES = 4
CMD_TOKEN_IMPERSONATE = 5
CMD_ENABLE_PRIVILEGE = 6
CMD_LS = 7
CMD_CAT = 8
CMD_MKDIR = 9
CMD_RM = 10
CMD_UPLOAD = 11
CMD_DOWNLOAD = 12
CMD_PS = 13
CMD_WHOAMI = 14
CMD_HOSTNAME = 15
CMD_GETPID = 16
CMD_EXEC = 17
CMD_SHELLCODEEXEC = 18
CMD_DISABLE_PRIVILEGE = 19
CMD_MEMREAD = 20
CMD_MODULELIST = 21
CMD_HANDLELIST = 22
CMD_ENV = 23
CMD_GETENV = 24
CMD_SETENV = 25
CMD_SLEEP = 26
CMD_PERSIST = 27
CMD_UNPERSIST = 28
CMD_MIGRATE = 29

COMMAND_SPECS = [
    {'id': CMD_KILL, 'name': 'kill', 'usage': 'kill', 'description': 'Stop the implant runtime'},
    {'id': CMD_INSPECT_TOKEN, 'name': 'inspect-token', 'usage': 'inspect-token', 'description': 'Display information about the current token'},
    {'id': CMD_PROCESS_TOKEN, 'name': 'process-token', 'usage': 'process-token <pid>', 'description': 'Return a summary of a target process token'},
    {'id': CMD_TOKEN_PRIVILEGES, 'name': 'token-privileges', 'usage': 'token-privileges <pid>', 'description': 'Return all privileges present on a target process token'},
    {'id': CMD_TOKEN_IMPERSONATE, 'name': 'token-impersonate', 'usage': 'token-impersonate <pid>', 'description': 'Attempt to impersonate the token of another process'},
    {'id': CMD_ENABLE_PRIVILEGE, 'name': 'enable-privilege', 'usage': 'enable-privilege <name>', 'description': 'Attempt to enable a privilege on the current token'},
    {'id': CMD_LS, 'name': 'ls', 'usage': 'ls [path]', 'description': 'List directory contents'},
    {'id': CMD_CAT, 'name': 'cat', 'usage': 'cat <file>', 'description': 'Display file contents'},
    {'id': CMD_MKDIR, 'name': 'mkdir', 'usage': 'mkdir <folder>', 'description': 'Create a new folder'},
    {'id': CMD_RM, 'name': 'rm', 'usage': 'rm <file/folder>', 'description': 'Remove an empty folder or file'},
    {'id': CMD_UPLOAD, 'name': 'upload', 'usage': 'upload <local> <remote>', 'description': 'Upload a file to the implant'},
    {'id': CMD_DOWNLOAD, 'name': 'download', 'usage': 'download <remote> <local>', 'description': 'Download a file from the implant'},
    {'id': CMD_PS, 'name': 'ps', 'usage': 'ps', 'description': 'List running processes'},
    {'id': CMD_WHOAMI, 'name': 'whoami', 'usage': 'whoami', 'description': 'Display the current security context of the implant'},
    {'id': CMD_HOSTNAME, 'name': 'hostname', 'usage': 'hostname', 'description': 'Return the host or computer name'},
    {'id': CMD_GETPID, 'name': 'getpid', 'usage': 'getpid', 'description': 'Return the implant process ID'},
    {'id': CMD_EXEC, 'name': 'exec', 'usage': 'exec <cmd>', 'description': 'Execute a program or command'},
    {'id': CMD_SHELLCODEEXEC, 'name': 'shellcodeexec', 'usage': 'shellcodeexec <path>', 'description': 'Execute raw shellcode from a file'},
    {'id': CMD_DISABLE_PRIVILEGE, 'name': 'disable-privilege', 'usage': 'disable-privilege <name>', 'description': 'Attempt to disable a privilege on the current token'},
    {'id': CMD_MEMREAD, 'name': 'memread', 'usage': 'memread <addr> <size>', 'description': 'Dump memory of a process'},
    {'id': CMD_MODULELIST, 'name': 'modulelist', 'usage': 'modulelist <pid>', 'description': 'List loaded modules of a process'},
    {'id': CMD_HANDLELIST, 'name': 'handlelist', 'usage': 'handlelist <pid>', 'description': 'List all handles for a given process'},
    {'id': CMD_ENV, 'name': 'env', 'usage': 'env', 'description': 'List all environment variables'},
    {'id': CMD_GETENV, 'name': 'getenv', 'usage': 'getenv <var>', 'description': 'Return value of an environment variable'},
    {'id': CMD_SETENV, 'name': 'setenv', 'usage': 'setenv <var> <val>', 'description': 'Create or modify an environment variable'},
    {'id': CMD_SLEEP, 'name': 'sleep', 'usage': 'sleep <interval>', 'description': 'Change the implant callback interval'},
    {'id': CMD_PERSIST, 'name': 'persist', 'usage': 'persist', 'description': 'Install persistence on the target'},
    {'id': CMD_UNPERSIST, 'name': 'unpersist', 'usage': 'unpersist', 'description': 'Removes the persistence on the target'},
    {'id': CMD_MIGRATE, 'name': 'migrate', 'usage': 'migrate <pid>', 'description': 'Inject the implant into another process'},
]

CMD_NAMES = {spec['id']: spec['name'] for spec in COMMAND_SPECS}
CMD_IDS = {spec['name']: spec['id'] for spec in COMMAND_SPECS}
