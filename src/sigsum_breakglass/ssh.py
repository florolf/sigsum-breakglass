import socket
import enum
import logging
import os

from pathlib import Path
from typing import Optional, Self

from nacl.signing import VerifyKey

from .utils import b64dec, b64enc

logger = logging.getLogger(__name__)


def msg_get_uint(bits: int, data: bytes) -> tuple[int, bytes]:
    assert bits % 8 == 0
    data_bytes = bits//8

    return int.from_bytes(data[0:data_bytes]), data[data_bytes:]


def msg_get_byte(data: bytes) -> tuple[int, bytes]:
    return data[0], data[1:]


def msg_get_bytes(data: bytes) -> tuple[bytes, bytes]:
    l = int.from_bytes(data[0:4])
    return data[4:4+l], data[4+l:]


def msg_get_string(data: bytes) -> tuple[str, bytes]:
    s, rest = msg_get_bytes(data)
    return s.decode(), rest


class MsgBuilder:
    def __init__(self):
        self.buf = bytearray()

    def put_int(self, bits: int, value: int):
        assert bits % 8 == 0
        data_bytes = bits//8

        self.buf.extend(value.to_bytes(data_bytes))

    def put_bytes(self, data: bytes):
        self.put_int(32, len(data))
        self.buf.extend(data)

    def put_string(self, s: str):
        self.put_bytes(s.encode())

    def append_raw(self, data: bytes):
        self.buf.extend(data)

    def get(self) -> bytes:
        return bytes(self.buf)


class Ed25519Key:
    def __init__(self, pubkey: bytes, comment: Optional[str] = None):
        self.pubkey = pubkey
        self.comment = comment

        blob = MsgBuilder()
        blob.put_string('ssh-ed25519')
        blob.put_bytes(pubkey)
        self.blob = blob.get()

    @classmethod
    def from_blob(cls, blob: bytes, comment: Optional[str] = None) -> Self:
        key_type, blob = msg_get_string(blob)

        if key_type != 'ssh-ed25519':
            raise ValueError(f'unexpected key type {key_type} (!= ssh-ed25519)')

        pubkey, blob = msg_get_bytes(blob)

        return cls(pubkey, comment)

    @classmethod
    def from_line(cls, pubkey: str) -> Self:
        elements = pubkey.split(maxsplit=2)
        if len(elements) == 1:
            blob = elements[0]
            comment = None
        elif len(elements) == 2:
            blob = elements[1]
            comment = None
        else:
            blob = elements[1]
            comment = elements[2]

        blob = b64dec(blob)
        return cls.from_blob(blob, comment)

    @classmethod
    def from_file(cls, path: Path) -> Self:
        text = path.read_text().strip()
        return cls.from_line(text)

    def __str__(self) -> str:
        line = f'ssh-ed25519 {b64enc(self.blob)}'

        if self.comment is not None:
            line += f' {self.comment}'

        return line

    def verify(self, data: bytes, signature: bytes):
        vk = VerifyKey(self.pubkey)
        vk.verify(data, signature)

class AgentCodes(enum.IntEnum):
    FAILURE                           = 5
    SUCCESS                           = 6
    CMD_REQUEST_IDENTITIES            = 11
    IDENTITIES_ANSWER                 = 12
    CMD_SIGN_REQUEST                  = 13
    SIGN_RESPONSE                     = 14
    CMD_ADD_IDENTITY                  = 17
    CMD_REMOVE_IDENTITY               = 18
    CMD_REMOVE_ALL_IDENTITIES         = 19
    CMD_ADD_SMARTCARD_KEY             = 20
    CMD_REMOVE_SMARTCARD_KEY          = 21
    CMD_LOCK                          = 22
    CMD_UNLOCK                        = 23
    CMD_ADD_ID_CONSTRAINED            = 25
    CMD_ADD_SMARTCARD_KEY_CONSTRAINED = 26
    CMD_EXTENSION                     = 27
    EXTENSION_FAILURE                 = 28
    EXTENSION_RESPONSE                = 29


class Agent:
    def __init__(self, path: Optional[Path] = None):
        if path is None:
            path = Path(os.environ['SSH_AUTH_SOCK'])

        self.path = path
        self.socket = None

    def ensure_connected(self):
        if self.socket:
            return

        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(str(self.path))

    def _recv(self, l: int) -> bytes:
        assert self.socket is not None

        result = bytearray()

        while len(result) < l:
            data = self.socket.recv(l - len(result))
            if not data:
                self.socket = None
                raise RuntimeError('socket closed unexpectedly')

            result.extend(data)

        return bytes(result)

    def recv(self) -> tuple[AgentCodes, bytes]:
        header = self._recv(5)
        l = int.from_bytes(header[0:4])
        retcode = AgentCodes(header[4])

        return retcode, self._recv(l-1)

    def call(self, cmd: AgentCodes, payload: bytes) -> tuple[AgentCodes, bytes]:
        tx = bytearray()

        l = 1 + len(payload)
        tx.extend(l.to_bytes(4))
        tx.extend(cmd.to_bytes(1))
        tx.extend(payload)

        self.ensure_connected()
        self.socket.sendall(tx)

        return self.recv()

    def sign(self, key: Ed25519Key, data: bytes) -> bytes:
        request = MsgBuilder()
        request.put_bytes(key.blob)
        request.put_bytes(data)
        request.put_int(32, 0)

        retcode, response = self.call(AgentCodes.CMD_SIGN_REQUEST, request.get())

        if retcode != AgentCodes.SIGN_RESPONSE:
            raise RuntimeError(f'got unexpected response {retcode}')

        signature_blob, response = msg_get_bytes(response)
        signature_type, signature_payload = msg_get_string(signature_blob)
        if signature_type != 'ssh-ed25519':
            raise RuntimeError(f'unexpected signature type {signature_type} (!= ssh-ed25519)')

        signature = msg_get_bytes(signature_payload)[0]

        return signature
