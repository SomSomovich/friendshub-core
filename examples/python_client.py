#!/usr/bin/env python3
"""Minimal FriendsHub client using the C ABI.

The library is loaded through ctypes; no bindings, no code generation. Run:

    python examples/python_client.py

Edit the CONFIG at the top first. The script inspects the local database,
and if the device is already initialized, starts the websocket and pumps
events. Otherwise it prints the sequence of calls that would complete setup.

This is a skeleton for a first integration test, not a production client.
"""

import ctypes
import json
import platform
import time
from pathlib import Path


# ---- adjust these -------------------------------------------------------
API_BASE = "https://api.fh.somuch-system.su"
WS_URL = "wss://api.fh.somuch-system.su/ws"
DB_PATH = str(Path.home() / ".friendshub" / "python-example.db")
PASSWORD = "correct horse battery staple"
DEVICE_NAME = "python-" + platform.system().lower()

# Method IDs, mirroring docs/ffi.md.
M_PING = 0x00000001
M_VERSION = 0x00000002

M_REGISTER = 0x00010001
M_LOGIN = 0x00010002
M_ME = 0x00010005

M_INIT_DEVICE = 0x00050004
M_INIT_STATUS = 0x00050005

M_SEND_MESSAGE = 0x00040004

M_WS_START = 0x00FF0001


class FhBuffer(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("len", ctypes.c_size_t),
        ("cap", ctypes.c_size_t),
    ]


def load_library():
    here = Path(__file__).resolve().parent.parent
    system = platform.system()
    if system == "Windows":
        name = "friendshub_core.dll"
    elif system == "Darwin":
        name = "libfriendshub_core.dylib"
    else:
        name = "libfriendshub_core.so"

    for candidate in [here / "target" / "debug" / name, here / "target" / "release" / name]:
        if candidate.exists():
            lib_path = candidate
            break
    else:
        raise SystemExit("library not found; run cargo build first (looked for " + name + ")")

    lib = ctypes.CDLL(str(lib_path))

    lib.fh_abi_version.restype = ctypes.c_uint32

    lib.fh_init.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(FhBuffer),
    ]
    lib.fh_init.restype = ctypes.c_int32

    lib.fh_destroy.argtypes = [ctypes.c_void_p]
    lib.fh_destroy.restype = None

    lib.fh_call.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(FhBuffer),
    ]
    lib.fh_call.restype = ctypes.c_int32

    lib.fh_poll_event.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(FhBuffer),
    ]
    lib.fh_poll_event.restype = ctypes.c_int32

    lib.fh_ack_event.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
    lib.fh_ack_event.restype = ctypes.c_int32

    lib.fh_buffer_free.argtypes = [ctypes.POINTER(FhBuffer)]
    lib.fh_buffer_free.restype = None

    return lib


def buf_to_bytes(buf):
    if not buf.data or buf.len == 0:
        return b""
    return ctypes.string_at(ctypes.cast(buf.data, ctypes.c_void_p), buf.len)


class Client:
    def __init__(self, lib):
        self.lib = lib
        self.handle = ctypes.c_void_p()

    def init(self, config):
        raw = json.dumps(config).encode("utf-8")
        arr = (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw)
        buf = FhBuffer()
        rc = self.lib.fh_init(arr, len(raw), ctypes.byref(self.handle), ctypes.byref(buf))
        return self._check(rc, buf, "fh_init")

    def call(self, method_id, payload=None):
        raw = json.dumps(payload).encode("utf-8") if payload is not None else b""
        arr = (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw) if raw else None
        buf = FhBuffer()
        rc = self.lib.fh_call(self.handle, method_id, arr, len(raw), ctypes.byref(buf))
        return self._check(rc, buf, "fh_call(0x%08x)" % method_id)

    def poll_event(self, timeout_ms=5000):
        buf = FhBuffer()
        rc = self.lib.fh_poll_event(self.handle, timeout_ms, ctypes.byref(buf))
        if rc != 0:
            self._check(rc, buf, "fh_poll_event")
        data = buf_to_bytes(buf)
        self.lib.fh_buffer_free(ctypes.byref(buf))
        if not data:
            return None
        return json.loads(data.decode("utf-8"))

    def ack_event(self, event_id):
        rc = self.lib.fh_ack_event(self.handle, ctypes.c_uint64(event_id))
        if rc != 0:
            raise RuntimeError("fh_ack_event(%d) returned %d" % (event_id, rc))

    def close(self):
        if self.handle:
            self.lib.fh_destroy(self.handle)
            self.handle = None

    def _check(self, rc, buf, what):
        data = buf_to_bytes(buf)
        self.lib.fh_buffer_free(ctypes.byref(buf))
        if rc != 0:
            msg = data.decode("utf-8", errors="replace") if data else "(no body)"
            raise RuntimeError(what + " failed (rc=" + str(rc) + "): " + msg)
        return json.loads(data.decode("utf-8")) if data else None


def main():
    lib = load_library()
    print("friendshub-core ABI version: " + str(lib.fh_abi_version()))

    client = Client(lib)
    client.init({
        "api_base": API_BASE,
        "ws_url": WS_URL,
        "db_path": DB_PATH,
        "log_level": "info",
    })

    try:
        print("ping:    " + json.dumps(client.call(M_PING)))
        print("version: " + json.dumps(client.call(M_VERSION)))

        status = client.call(M_INIT_STATUS)
        print("status:  " + json.dumps(status))

        if not status.get("initialized"):
            print("")
            print("The database has no device identity yet. To finish setup, add")
            print("these calls to this script (or run them from a REPL):")
            print("")
            print("  client.call(M_REGISTER, {\"password\": PASSWORD})")
            print("  # note the fh_number from the response, then:")
            print("  client.call(M_LOGIN, {")
            print("      \"fh_number\": \"FH...\",")
            print("      \"password\": PASSWORD,")
            print("      \"device_number\": 1,")
            print("  })")
            print("  client.call(M_INIT_DEVICE, {\"name\": DEVICE_NAME})")
            return

        client.call(M_WS_START)
        print("")
        print("websocket started; polling events for 60 seconds")

        deadline = time.time() + 60
        while time.time() < deadline:
            event = client.poll_event(5000)
            if event is None:
                continue
            kind = event.get("kind")
            print("event: " + str(kind))
            if kind == "envelope_received":
                payload = event.get("payload", {})
                pt = payload.get("plaintext_hex")
                sender = payload.get("sender_account_id", "?")
                if pt:
                    text = bytes.fromhex(pt).decode("utf-8", errors="replace")
                    print("  from " + sender + ": " + text)
                else:
                    print("  (could not decrypt: ciphertext only)")
                if "id" in event:
                    client.ack_event(event["id"])
            elif kind == "ws_connected":
                print("  websocket connected")
            elif kind == "ws_disconnected":
                print("  websocket disconnected")
    finally:
        client.close()


if __name__ == "__main__":
    main()
