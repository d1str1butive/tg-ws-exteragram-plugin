import asyncio
import base64
import os
import socket as _socket
import ssl
import struct
import time
import threading
from typing import Dict, List, Optional, Set, Tuple

from base_plugin import BasePlugin, AppEvent
from ui.settings import Switch, Header
from client_utils import get_connections_manager
from org.telegram.messenger import SharedConfig, NotificationCenter

try:
    from javax.crypto import Cipher as JavaCipher
    from javax.crypto.spec import SecretKeySpec, IvParameterSpec
except ImportError:
    pass

__id__ = "tg_ws_proxy_plugin"
__name__ = "tg-ws"
__description__ = "Local SOCKS5 proxy masking telegram traffic as websocket."
__author__ = "d1str1butive (port), Flowseal (core)"
__version__ = "1.1.0"
__min_version__ = "11.12.0"

_TCP_NODELAY = True
_WS_POOL_SIZE = 4
_WS_POOL_MAX_AGE = 120.0

_TG_RANGES = [
    (struct.unpack('!I', _socket.inet_aton('185.76.151.0'))[0], struct.unpack('!I', _socket.inet_aton('185.76.151.255'))[0]),
    (struct.unpack('!I', _socket.inet_aton('149.154.160.0'))[0], struct.unpack('!I', _socket.inet_aton('149.154.175.255'))[0]),
    (struct.unpack('!I', _socket.inet_aton('91.105.192.0'))[0], struct.unpack('!I', _socket.inet_aton('91.105.193.255'))[0]),
    (struct.unpack('!I', _socket.inet_aton('91.108.0.0'))[0], struct.unpack('!I', _socket.inet_aton('91.108.255.255'))[0]),
]

_IP_TO_DC: Dict[str, Tuple[int, bool]] = {
    '149.154.175.50': (1, False), '149.154.175.51': (1, False), '149.154.175.53': (1, False), '149.154.175.54': (1, False), '149.154.175.52': (1, True),
    '149.154.167.41': (2, False), '149.154.167.50': (2, False), '149.154.167.51': (2, False), '149.154.167.220': (2, False), '95.161.76.100':  (2, False),
    '149.154.167.151': (2, True), '149.154.167.222': (2, True), '149.154.167.223': (2, True), '149.154.162.123': (2, True),
    '149.154.175.100': (3, False), '149.154.175.101': (3, False), '149.154.175.102': (3, True),
    '149.154.167.91': (4, False), '149.154.167.92': (4, False), '149.154.164.250': (4, True), '149.154.166.120': (4, True),
    '149.154.166.121': (4, True), '149.154.167.118': (4, True), '149.154.165.111': (4, True),
    '91.108.56.100': (5, False), '91.108.56.101': (5, False), '91.108.56.116': (5, False), '91.108.56.126': (5, False), '149.154.171.5':  (5, False),
    '91.108.56.102': (5, True), '91.108.56.128': (5, True), '91.108.56.151': (5, True),
    '91.105.192.100': (203, False),
}

_ws_blacklist: Set[Tuple[int, bool]] = set()
_dc_fail_until: Dict[Tuple[int, bool], float] = {}
_DC_FAIL_COOLDOWN = 60.0

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

def _set_sock_opts(transport):
    sock = transport.get_extra_info('socket')
    if sock is None:
        return

    if _TCP_NODELAY:
        try:
            sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        except Exception:
            pass

    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_KEEPALIVE, 1)
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_KEEPIDLE, 15)
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_KEEPINTVL, 5)
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_KEEPCNT, 3)
    except Exception:
        pass

def _get_java_cipher(key_raw: bytes, iv: bytes):
    secret_key = SecretKeySpec(key_raw, "AES")
    iv_spec = IvParameterSpec(iv)
    cipher = JavaCipher.getInstance("AES/CTR/NoPadding")
    cipher.init(JavaCipher.ENCRYPT_MODE, secret_key, iv_spec)
    return cipher

def _dc_from_init(data: bytes) -> Tuple[Optional[int], bool]:
    try:
        cipher = _get_java_cipher(bytes(data[8:40]), bytes(data[40:56]))
        key_stream = cipher.update(b'\x00' * 64)

        if key_stream:
            key_stream = bytes(key_stream)
        else:
            return None, False

        plain = bytes(a ^ b for a, b in zip(data[56:64], key_stream[56:64]))
        protocol = struct.unpack('<I', plain[0:4])[0]
        dc_raw = struct.unpack('<h', plain[4:6])[0]

        valid_protocols = (0xEFEFEFEF, 0xEEEEEEEE, 0xDDDDDDDD)
        if protocol in valid_protocols:
            dc = abs(dc_raw)
            if 1 <= dc <= 1000:
                is_media = (dc_raw < 0)
                return dc, is_media
    except Exception:
        pass

    return None, False

def _patch_init_dc(data: bytes, dc: int) -> bytes:
    if len(data) < 64:
        return data

    new_dc = struct.pack('<h', dc)
    try:
        cipher = _get_java_cipher(bytes(data[8:40]), bytes(data[40:56]))
        key_stream = cipher.update(b'\x00' * 64)

        if key_stream:
            key_stream = bytes(key_stream)
        else:
            return data

        patched_data = bytearray(data[:64])
        patched_data[60] = key_stream[60] ^ new_dc[0]
        patched_data[61] = key_stream[61] ^ new_dc[1]

        if len(data) > 64:
            return bytes(patched_data) + data[64:]
        return bytes(patched_data)
    except Exception:
        return data

class _MsgSplitter:
    def __init__(self, init_data: bytes):
        self.cipher = _get_java_cipher(bytes(init_data[8:40]), bytes(init_data[40:56]))
        self.cipher.update(b'\x00' * 64)

    def split(self, chunk: bytes) -> List[bytes]:
        try:
            out = self.cipher.update(chunk)
            plain = bytes(out) if out else b''
        except Exception:
            return [chunk]

        boundaries = []
        pos = 0
        while pos < len(plain):
            first_byte = plain[pos]
            if first_byte == 0x7f:
                if pos + 4 > len(plain):
                    break
                msg_len = (struct.unpack_from('<I', plain, pos + 1)[0] & 0xFFFFFF) * 4
                pos += 4
            else:
                msg_len = first_byte * 4
                pos += 1

            if msg_len == 0 or pos + msg_len > len(plain):
                break

            pos += msg_len
            boundaries.append(pos)

        if len(boundaries) <= 1:
            return [chunk]

        parts = []
        prev_boundary = 0
        for boundary in boundaries:
            parts.append(chunk[prev_boundary:boundary])
            prev_boundary = boundary

        if prev_boundary < len(chunk):
            parts.append(chunk[prev_boundary:])

        return parts

class WsHandshakeError(Exception):
    def __init__(self, status_code: int, status_line: str, headers: dict = None, location: str = None):
        self.status_code = status_code
        self.status_line = status_line
        self.headers = headers or {}
        self.location = location
        super().__init__(f"HTTP {status_code}: {status_line}")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)

def _xor_mask(data: bytes, mask: bytes) -> bytes:
    if not data:
        return data
    data_length = len(data)
    mask_repeated = (mask * (data_length // 4 + 1))[:data_length]
    masked_int = int.from_bytes(data, 'big') ^ int.from_bytes(mask_repeated, 'big')
    return masked_int.to_bytes(data_length, 'big')

class RawWebSocket:
    OP_CONTINUATION = 0x0
    OP_TEXT = 0x1
    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False

    @staticmethod
    async def connect(ip: str, domain: str, path: str = '/apiws', timeout: float = 20.0) -> 'RawWebSocket':
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=_ssl_ctx, server_hostname=domain, limit=1048576),
            timeout=timeout
        )
        _set_sock_opts(writer.transport)

        ws_key = base64.b64encode(os.urandom(16)).decode()

        request_headers = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {domain}\r\n'
            f'Upgrade: websocket\r\n'
            f'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {ws_key}\r\n'
            f'Sec-WebSocket-Version: 13\r\n'
            f'Sec-WebSocket-Protocol: binary\r\n'
            f'Origin: https://web.telegram.org\r\n'
            f'User-Agent: Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0\r\n\r\n'
        )

        writer.write(request_headers.encode())
        await writer.drain()

        response_lines: list[str] = []
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                if line in (b'\r\n', b'\n', b''):
                    break
                response_lines.append(line.decode('utf-8', errors='replace').strip())
        except asyncio.TimeoutError:
            writer.close()
            raise

        if not response_lines:
            writer.close()
            raise WsHandshakeError(0, 'empty response')

        first_line = response_lines[0]
        parts = first_line.split(' ', 2)

        try:
            status_code = int(parts[1]) if len(parts) >= 2 else 0
        except ValueError:
            status_code = 0

        if status_code == 101:
            return RawWebSocket(reader, writer)

        headers: dict[str, str] = {}
        for header_line in response_lines[1:]:
            if ':' in header_line:
                key, value = header_line.split(':', 1)
                headers[key.strip().lower()] = value.strip()

        writer.close()
        raise WsHandshakeError(status_code, first_line, headers, location=headers.get('location'))

    async def send(self, data: bytes):
        if self._closed:
            raise ConnectionError("WebSocket closed")

        frame = self._build_frame(self.OP_BINARY, data, mask=True)
        self.writer.write(frame)
        if self.writer.transport.get_write_buffer_size() > 65536:
            await self.writer.drain()

    async def send_batch(self, parts: List[bytes]):
        if self._closed:
            raise ConnectionError("WebSocket closed")

        for part in parts:
            frame = self._build_frame(self.OP_BINARY, part, mask=True)
            self.writer.write(frame)

        if self.writer.transport.get_write_buffer_size() > 65536:
            await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        while not self._closed:
            opcode, payload = await self._read_frame()

            if opcode == self.OP_CLOSE:
                self._closed = True
                try:
                    close_payload = payload[:2] if payload else b''
                    reply = self._build_frame(self.OP_CLOSE, close_payload, mask=True)
                    self.writer.write(reply)
                    await self.writer.drain()
                except Exception:
                    pass
                return None

            if opcode == self.OP_PING:
                try:
                    pong = self._build_frame(self.OP_PONG, payload, mask=True)
                    self.writer.write(pong)
                    await self.writer.drain()
                except Exception:
                    pass
                continue

            if opcode == self.OP_PONG:
                continue

            if opcode in (self.OP_TEXT, self.OP_BINARY):
                return payload

        return None

    async def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.writer.write(self._build_frame(self.OP_CLOSE, b'', mask=True))
            await self.writer.drain()
        except Exception:
            pass

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    @staticmethod
    def _build_frame(opcode: int, data: bytes, mask: bool = False) -> bytes:
        header = bytearray()
        header.append(0x80 | opcode)

        data_length = len(data)
        mask_bit = 0x80 if mask else 0x00

        if data_length < 126:
            header.append(mask_bit | data_length)
        elif data_length < 65536:
            header.append(mask_bit | 126)
            header.extend(struct.pack('>H', data_length))
        else:
            header.append(mask_bit | 127)
            header.extend(struct.pack('>Q', data_length))

        if mask:
            mask_key = os.urandom(4)
            header.extend(mask_key)
            return bytes(header) + _xor_mask(data, mask_key)

        return bytes(header) + data

    async def _read_frame(self) -> Tuple[int, bytes]:
        header_bytes = await self.reader.readexactly(2)
        opcode = header_bytes[0] & 0x0F
        is_masked = bool(header_bytes[1] & 0x80)
        payload_length = header_bytes[1] & 0x7F

        if payload_length == 126:
            length_bytes = await self.reader.readexactly(2)
            payload_length = struct.unpack('>H', length_bytes)[0]
        elif payload_length == 127:
            length_bytes = await self.reader.readexactly(8)
            payload_length = struct.unpack('>Q', length_bytes)[0]

        if is_masked:
            mask_key = await self.reader.readexactly(4)
            payload = await self.reader.readexactly(payload_length)
            return opcode, _xor_mask(payload, mask_key)

        payload = await self.reader.readexactly(payload_length)
        return opcode, payload

class _WsPool:
    def __init__(self):
        self._idle: Dict[Tuple[int, bool], list] = {}
        self._refilling: Set[Tuple[int, bool]] = set()

    async def get(self, dc: int, is_media: bool, target_ip: str, domains: List[str]) -> Optional[RawWebSocket]:
        key = (dc, is_media)
        now = time.monotonic()

        bucket = self._idle.get(key, [])
        while bucket:
            ws, created = bucket.pop(0)
            age = now - created
            if age > _WS_POOL_MAX_AGE or ws._closed:
                asyncio.create_task(self._quiet_close(ws))
                continue
            self._schedule_refill(key, target_ip, domains)
            return ws

        self._schedule_refill(key, target_ip, domains)
        return None

    def _schedule_refill(self, key, target_ip, domains):
        if key in self._refilling:
            return
        self._refilling.add(key)
        asyncio.create_task(self._refill(key, target_ip, domains))

    async def _refill(self, key, target_ip, domains):
        try:
            bucket = self._idle.setdefault(key, [])
            needed = _WS_POOL_SIZE - len(bucket)
            if needed <= 0:
                return
            tasks = []
            for _ in range(needed):
                tasks.append(asyncio.create_task(self._connect_one(target_ip, domains)))
            for t in tasks:
                try:
                    ws = await t
                    if ws:
                        bucket.append((ws, time.monotonic()))
                except Exception:
                    pass
        finally:
            self._refilling.discard(key)

    @staticmethod
    async def _connect_one(target_ip, domains) -> Optional[RawWebSocket]:
        for domain in domains:
            try:
                ws = await RawWebSocket.connect(target_ip, domain, timeout=8)
                return ws
            except WsHandshakeError as exc:
                if exc.is_redirect:
                    continue
                return None
            except Exception:
                return None
        return None

    @staticmethod
    async def _quiet_close(ws):
        try:
            await ws.close()
        except Exception:
            pass

    async def warmup(self, dc_opt: Dict[int, str]):
        for dc, target_ip in dc_opt.items():
            if target_ip is None:
                continue
            for is_media in (False, True):
                domains = _ws_domains(dc, is_media)
                key = (dc, is_media)
                self._schedule_refill(key, target_ip, domains)

_ws_pool = _WsPool()

def _is_telegram_ip(ip_address: str) -> bool:
    try:
        ip_num = struct.unpack('!I', _socket.inet_aton(ip_address))[0]
        for lower_bound, upper_bound in _TG_RANGES:
            if lower_bound <= ip_num <= upper_bound:
                return True
        return False
    except OSError:
        return False

def _is_http_transport(data: bytes) -> bool:
    return data.startswith(b'POST ') or data.startswith(b'GET ') or \
           data.startswith(b'HEAD ') or data.startswith(b'OPTIONS ')

def _ws_domains(dc: int, is_media: bool) -> List[str]:
    if is_media is None or is_media:
        return [f'kws{dc}-1.web.telegram.org', f'kws{dc}.web.telegram.org']
    return [f'kws{dc}.web.telegram.org', f'kws{dc}-1.web.telegram.org']

async def _bridge_ws(local_reader, local_writer, ws: RawWebSocket, label, dc=None, dst=None, port=None, is_media=False, splitter=None):
    async def tcp_to_ws():
        try:
            while True:
                chunk = await local_reader.read(65536)
                if not chunk:
                    break
                if splitter:
                    parts = splitter.split(chunk)
                    if len(parts) > 1:
                        await ws.send_batch(parts)
                    else:
                        await ws.send(parts[0])
                else:
                    await ws.send(chunk)
        except Exception:
            return

    async def ws_to_tcp():
        try:
            while True:
                data = await ws.recv()
                if data is None:
                    break
                local_writer.write(data)
                if local_writer.transport.get_write_buffer_size() > 65536:
                    await local_writer.drain()
        except Exception:
            return

    tasks = [asyncio.create_task(tcp_to_ws()), asyncio.create_task(ws_to_tcp())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        try:
            await ws.close()
        except Exception:
            pass
        try:
            local_writer.close()
            await local_writer.wait_closed()
        except Exception:
            pass

async def _bridge_tcp(local_reader, local_writer, remote_reader, remote_writer, label, dc=None, dst=None, port=None, is_media=False):
    async def forward_stream(source_reader, destination_writer):
        try:
            while True:
                data = await source_reader.read(65536)
                if not data:
                    break
                destination_writer.write(data)
                if destination_writer.transport.get_write_buffer_size() > 65536:
                    await destination_writer.drain()
        except Exception:
            pass

    tasks = [
        asyncio.create_task(forward_stream(local_reader, remote_writer)),
        asyncio.create_task(forward_stream(remote_reader, local_writer))
    ]

    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        for writer_to_close in (local_writer, remote_writer):
            try:
                writer_to_close.close()
                await writer_to_close.wait_closed()
            except Exception:
                pass

def _socks5_reply(status_code: int) -> bytes:
    return bytes([0x05, status_code, 0x00, 0x01]) + b'\x00' * 6

async def _tcp_fallback(local_reader, local_writer, destination_ip, port, initial_data, label, dc=None, is_media=False):
    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(destination_ip, port, limit=1048576),
            timeout=20.0
        )
    except Exception:
        return False

    remote_writer.write(initial_data)
    await remote_writer.drain()
    await _bridge_tcp(local_reader, local_writer, remote_reader, remote_writer, label, dc=dc, dst=destination_ip, port=port, is_media=is_media)
    return True

class WsProxyPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.proxy_thread = None
        self.loop = None
        self.server = None
        self.default_port = 1080
        self.dc_opt = {2: '149.154.167.220', 4: '149.154.167.220'}

    def enable_client_proxy(self, port: int):
        try:
            SharedConfig.loadProxyList()
            proxy_info = SharedConfig.ProxyInfo("127.0.0.1", port, "", "", "")
            SharedConfig.addProxy(proxy_info)
            SharedConfig.currentProxy = proxy_info
            SharedConfig.saveConfig()
        except Exception:
            pass

        try:
            conn_manager = get_connections_manager()
            conn_manager.setProxySettings(True, "127.0.0.1", port, "", "", "")
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged)
        except Exception:
            pass

    def disable_client_proxy(self):
        try:
            if SharedConfig.currentProxy and SharedConfig.currentProxy.address == "127.0.0.1":
                SharedConfig.currentProxy = None
                SharedConfig.saveConfig()
        except Exception:
            pass

        try:
            conn_manager = get_connections_manager()
            conn_manager.setProxySettings(False, "", 0, "", "", "")
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged)
        except Exception:
            pass

    def on_plugin_load(self):
        proxy_port = self.default_port
        self.proxy_thread = threading.Thread(target=self.run_proxy_server, args=(proxy_port,), daemon=True)
        self.proxy_thread.start()

        threading.Timer(0.5, lambda: self.enable_client_proxy(proxy_port)).start()

    def on_app_event(self, event_type: AppEvent):
        if event_type == AppEvent.START or event_type == AppEvent.RESUME:
            self.enable_client_proxy(self.default_port)

    def on_plugin_unload(self):
        self.disable_client_proxy()
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.stop_server_internal)
        if self.proxy_thread:
            self.proxy_thread.join(timeout=2.0)

    def stop_server_internal(self):
        if self.server:
            self.server.close()
        for task in asyncio.all_tasks(self.loop):
            task.cancel()
        self.loop.stop()

    def run_proxy_server(self, port):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.create_task(_ws_pool.warmup(self.dc_opt))
        try:
            self.server = self.loop.run_until_complete(
                asyncio.start_server(self.handle_client, '127.0.0.1', port, limit=1048576)
            )
            self.loop.run_forever()
        except Exception:
            pass
        finally:
            self.loop.close()

    def create_settings(self) -> list:
        return [
            Header(text="Settings WS Proxy"),
            Switch(key="auto_start", text="Auto start", default=True)
        ]

    async def handle_client(self, local_reader, local_writer):
        _set_sock_opts(local_writer.transport)

        try:
            socks_handshake_header = await asyncio.wait_for(local_reader.readexactly(2), timeout=10)
            socks_version = socks_handshake_header[0]

            if socks_version != 5:
                local_writer.close()
                return

            num_methods = socks_handshake_header[1]
            await local_reader.readexactly(num_methods)

            local_writer.write(b'\x05\x00')
            await local_writer.drain()

            request_header = await asyncio.wait_for(local_reader.readexactly(4), timeout=10)
            _, cmd, _, address_type = request_header

            if cmd != 1:
                local_writer.write(_socks5_reply(0x07))
                await local_writer.drain()
                local_writer.close()
                return

            if address_type == 1:
                raw_ip = await local_reader.readexactly(4)
                destination_ip = _socket.inet_ntoa(raw_ip)
            elif address_type == 3:
                domain_length = (await local_reader.readexactly(1))[0]
                destination_ip = (await local_reader.readexactly(domain_length)).decode()
            elif address_type == 4:
                raw_ipv6 = await local_reader.readexactly(16)
                destination_ip = _socket.inet_ntop(_socket.AF_INET6, raw_ipv6)
            else:
                local_writer.write(_socks5_reply(0x08))
                await local_writer.drain()
                local_writer.close()
                return

            destination_port = struct.unpack('!H', await local_reader.readexactly(2))[0]

            if not _is_telegram_ip(destination_ip):
                try:
                    remote_reader, remote_writer = await asyncio.wait_for(
                        asyncio.open_connection(destination_ip, destination_port, limit=1048576),
                        timeout=10
                    )
                except Exception:
                    local_writer.write(_socks5_reply(0x05))
                    await local_writer.drain()
                    local_writer.close()
                    return

                local_writer.write(_socks5_reply(0x00))
                await local_writer.drain()

                tasks = [
                    asyncio.create_task(self.pipe_stream(local_reader, remote_writer)),
                    asyncio.create_task(self.pipe_stream(remote_reader, local_writer))
                ]
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in tasks:
                    task.cancel()
                return

            local_writer.write(_socks5_reply(0x00))
            await local_writer.drain()

            try:
                initial_data = await asyncio.wait_for(local_reader.readexactly(64), timeout=15)
            except asyncio.IncompleteReadError:
                return

            if _is_http_transport(initial_data):
                local_writer.close()
                return

            dc, is_media = _dc_from_init(initial_data)
            init_patched = False

            if destination_ip in _IP_TO_DC:
                real_dc, real_is_media = _IP_TO_DC[destination_ip]
                if real_dc in self.dc_opt:
                    dc = real_dc
                    is_media = real_is_media
                    initial_data = _patch_init_dc(initial_data, -dc if is_media else dc)
                    init_patched = True
            elif dc is not None and dc in self.dc_opt:
                pass

            if dc is None or dc not in self.dc_opt:
                await _tcp_fallback(local_reader, local_writer, destination_ip, destination_port, initial_data, None)
                return

            dc_key = (dc, is_media)
            current_time = time.monotonic()

            if dc_key in _ws_blacklist or current_time < _dc_fail_until.get(dc_key, 0):
                await _tcp_fallback(local_reader, local_writer, destination_ip, destination_port, initial_data, None, dc=dc, is_media=is_media)
                return

            domains = _ws_domains(dc, is_media)
            target_ip = self.dc_opt[dc]
            
            websocket_conn = await _ws_pool.get(dc, is_media, target_ip, domains)

            if not websocket_conn:
                for domain in domains:
                    try:
                        websocket_conn = await RawWebSocket.connect(target_ip, domain, timeout=20.0)
                        break
                    except WsHandshakeError as exc:
                        if exc.is_redirect:
                            continue
                    except Exception:
                        pass

            if websocket_conn is None:
                _dc_fail_until[dc_key] = current_time + _DC_FAIL_COOLDOWN
                await _tcp_fallback(local_reader, local_writer, destination_ip, destination_port, initial_data, None, dc=dc, is_media=is_media)
                return

            message_splitter = None
            if init_patched:
                try:
                    message_splitter = _MsgSplitter(initial_data)
                except Exception:
                    pass

            await websocket_conn.send(initial_data)
            await _bridge_ws(local_reader, local_writer, websocket_conn, None, dc=dc, dst=destination_ip, port=destination_port, is_media=is_media, splitter=message_splitter)

        except Exception:
            pass
        finally:
            try:
                local_writer.close()
            except Exception:
                pass

    async def pipe_stream(self, reader_stream, writer_stream):
        try:
            while True:
                data = await reader_stream.read(65536)
                if not data:
                    break
                writer_stream.write(data)
                if writer_stream.transport.get_write_buffer_size() > 65536:
                    await writer_stream.drain()
        except Exception:
            pass
        finally:
            try:
                writer_stream.close()
                await writer_stream.wait_closed()
            except Exception:
                pass

class Hook(WsProxyPlugin):
    pass

__plugin__ = Hook