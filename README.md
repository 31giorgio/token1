# Operation-Windows-Freedom
SY486K Final Project

Windows Implant
The implant is the Windows-resident component that checks in with the C2 server, receives tasks, executes them, and returns results.

The implant must be implemented in C and must make meaningful use of Windows APIs.

The implant can be implemented either as a .exe or .dll

The implant must use a beaconing model of communication (make periodic callbacks to the C2 server)


Custom C2 Server
The server must:

Accept implant registrations and callbacks

Manage tasking for one or more implants

Receive and store task results

Maintain enough state to support realistic operator workflows

The C2 server can be written in any language.


Operator Interface
The operator interface must allow a human operator to:

View connected implants

Issue tasks

Inspect returned results

Distinguish success, failure, and partial failure cases

The operator interface can either be a CLI or a GUI. You can use any language to implement the operator interface.


Custom Communications Protocol
Your team must define and implement a custom C2 protocol that blends as a common network protocol such as:

HTTP

HTTPS

DNS

RTP

QUIC

ICMP

SMTP

IRC


The protocol must be documented and must include:

Message structure

Tasking format

Result format

Identifiers and metadata

Error handling behavior

Session or host tracking design


Your custom communications protocol should be properly parsed in Wireshark as the protocol you are trying to blend as.


Encrypted Communications
All tasking and result data must be protected with strong encryption.


Requirements:

commands and results may not be sent in plaintext

Integrity protection must be provided

Keying material and session setup must be documented

Do not invent your own cryptographic primitives

Using Windows CNG or another reputable cryptographic library is acceptable. Ad hoc or "roll your own" cryptography is not.

# Required Operator Commands
Filesystem
ls: list directory contents

cat: display file contents for a text file

mkdir: create a directory

rm: delete a file or directory with clear failure reporting

upload: transfer a file from operator to implant

download: transfer a file from implant to operator


System Enumeration
ps: enumerate running processes with at least PID and image name

whoami: display the current security context of the implant

hostname: return the host or computer name

getpid: return the implant process ID


Execution
exec: execute a program or command and return output, exit status, or error information

shellcodeexec: execute shellcode in either the current or another process (process injection)


Token Manipulation
inspect-token: Display information about the current token

enable-privilege: Enable a specific privilege on the current token 

disable-privilege: Disable a specific privilege on the current token

token-impersonate: Impersonate another process's token


Memory and Object Inspection
memread: Dump the memory of a specific process given an address and a size

modulelist: List the loaded modules of a specified process (including the address it's loaded at)

handlelist: List all the handles for a given process


Environment
env: list all environment variables for the current process

getenv: return the value of a named environment variable

setenv: create or modify an environment variable for the implant process


Implant Management
sleep: change the implant callback interval

kill: stops the implant from running

persist: install persistence on the target

unpersist: removes the persistence on the target

migrate: inject the implant into another process
