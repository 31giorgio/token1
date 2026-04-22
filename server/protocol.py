import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

MSG_ERROR = 0xFFFFFFFF

MSG_AGENT_GET_TASK = 0x10000001
MSG_AGENT_POST_RESULT = 0x10000002
MSG_OPERATOR_SUBMIT_TASK = 0x10000003
MSG_OPERATOR_GET_RESULT = 0x10000004
MSG_SERVER_NO_TASK = 0x10000005
MSG_SERVER_TASK = 0x10000006
MSG_SERVER_ACK = 0x10000007
MSG_SERVER_RESULT = 0x10000008
MSG_SERVER_PENDING = 0x10000009
MSG_OPERATOR_LIST_PENDING = 0x1000000A
MSG_SERVER_TASK_LIST = 0x1000000B
MSG_OPERATOR_LIST_HISTORY = 0x1000000C
MSG_SERVER_TASK_HISTORY = 0x1000000D

DEFAULT_AGENT_ID = 1

TASK_STATE_QUEUED_CODE = 1
TASK_STATE_LEASED_CODE = 2
TASK_STATE_COMPLETED_CODE = 3

keyFile = "C:\\Users\\m271764\\sy486k\\Operation-Windows-Freedom\\server\\key.bin"
IV = b"\xf0\x01\x98\xcb\xd6\x53\x0e\x36\xb5\xe1\x0d\x16\xb2\xe1\xf7\xb6"

MESSAGE_NAMES = {
    MSG_ERROR: "MSG_ERROR",
    MSG_AGENT_GET_TASK: "MSG_AGENT_GET_TASK",
    MSG_AGENT_POST_RESULT: "MSG_AGENT_POST_RESULT",
    MSG_OPERATOR_SUBMIT_TASK: "MSG_OPERATOR_SUBMIT_TASK",
    MSG_OPERATOR_GET_RESULT: "MSG_OPERATOR_GET_RESULT",
    MSG_SERVER_NO_TASK: "MSG_SERVER_NO_TASK",
    MSG_SERVER_TASK: "MSG_SERVER_TASK",
    MSG_SERVER_ACK: "MSG_SERVER_ACK",
    MSG_SERVER_RESULT: "MSG_SERVER_RESULT",
    MSG_SERVER_PENDING: "MSG_SERVER_PENDING",
    MSG_OPERATOR_LIST_PENDING: "MSG_OPERATOR_LIST_PENDING",
    MSG_SERVER_TASK_LIST: "MSG_SERVER_TASK_LIST",
    MSG_OPERATOR_LIST_HISTORY: "MSG_OPERATOR_LIST_HISTORY",
    MSG_SERVER_TASK_HISTORY: "MSG_SERVER_TASK_HISTORY",
}


def encode_tlv(message_type, payload=b""):
    payload = struct.pack("<II", message_type, len(payload)) + payload
    payload = encrypt(payload)
    payload = struct.pack("<HHHHHH", 0, 0, len(payload), 0, 0, 0) + payload
    return payload

def decode_tlv(data):
    data = decrypt(data[12:])
    header = data[0:8]
    if header is None:
        return None

    message_type, length = struct.unpack("<II", header)
    payload = data[8:]
    if payload is None:
        return None

    return message_type, payload


'''
I used Gemini to write this implementation of AES CBC-mode
'''
def encrypt(payload):
    with open(keyFile, 'rb') as f:
        key = f.readlines()[0][-32:]
    cipher = AES.new(key, AES.MODE_CBC, IV)
    padded_data = pad(payload, AES.block_size)
    return cipher.encrypt(padded_data)


def decrypt(payload):
    with open(keyFile, 'rb') as f:
        key = f.readlines()[0][-32:]
    cipher = AES.new(key, AES.MODE_CBC, IV)
    decrypted_padded_data = cipher.decrypt(payload)
    return unpad(decrypted_padded_data, AES.block_size)