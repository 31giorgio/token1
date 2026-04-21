#pragma once

/* Auto-generated from shared/commands.csv. Do not edit directly. */

typedef enum _CMD_ID
{
    CMD_KILL = 1,
    CMD_INSPECT_TOKEN = 2,
    CMD_PROCESS_TOKEN = 3,
    CMD_TOKEN_PRIVILEGES = 4,
    CMD_TOKEN_IMPERSONATE = 5,
    CMD_ENABLE_PRIVILEGE = 6,
    CMD_LS = 7,
    CMD_CAT = 8,
    CMD_MKDIR = 9,
    CMD_RM = 10,
    CMD_UPLOAD = 11,
    CMD_DOWNLOAD = 12,
    CMD_PS = 13,
    CMD_WHOAMI = 14,
    CMD_HOSTNAME = 15,
    CMD_GETPID = 16,
    CMD_EXEC = 17,
    CMD_SHELLCODEEXEC = 18,
    CMD_DISABLE_PRIVILEGE = 19,
    CMD_MEMREAD = 20,
    CMD_MODULELIST = 21,
    CMD_HANDLELIST = 22,
    CMD_ENV = 23,
    CMD_GETENV = 24,
    CMD_SETENV = 25,
    CMD_SLEEP = 26,
    CMD_PERSIST = 27,
    CMD_UNPERSIST = 28,
    CMD_MIGRATE = 29,
    CMD_UNK
} CMD_ID;
