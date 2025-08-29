print("### NEPTUN.PY BUILD: 2025-08-29-LEN-FRAMING-NO-RECONNECT ###")
print("### NEPTUN.PY BUILD: 2025-08-29-LEN-FRAMING-NO-RECONNECT ###")

from six import string_types
import sys, traceback
import os
import socket, errno
import datetime
import time
import threading

import _thread as thread
import queue

"""
UDP on Windows 10 with several networks. You should set a primary network

1. Goto Control Panel > Network and Internet > Network Connections
2. Right click the desired connection (Higher Priority Connection)
3. Click Properties > Internet Protocol Version 4
4. Click Properties > Advanced
5. Uncheck 'Automatic Metric'
6. Enter 10 in 'Interface Metric'
7. Click OK
"""

PACKET_WHOIS = 0x49
PACKET_SYSTEM_STATE = 0x52
PACKET_COUNTER_NAME = 0x63
PACKET_COUNTER_STATE = 0x43
PACKET_SENSOR_NAME = 0x4E
PACKET_SENSOR_STATE = 0x53
PACKET_BACK_STATE = 0x42
PACKET_RECONNECT = 0x57
PACKET_SET_SYSTEM_STATE = 0x57
PACKET_ACK = 0xFB          # короткий ACK/keepalive
PACKET_BUSY = 0xFE         # «занят/повтори позже»

BROADCAST_PORT = 6350
BROADCAST_ADDRESS = '255.255.255.255'

SERVER_PORT = 6350

SOCKET_BUFSIZE = 1024


def time_delta(timestamp):
    if timestamp is None:
        return 9999999
    else:
        return (datetime.datetime.now() - timestamp).total_seconds()


def crc16(data, data_len=0):
    """
    CRC16 (CCITT, poly 0x1021, init 0xFFFF), big-endian
    """
    polynom = 0x1021
    crc16ret = 0xFFFF
    if data_len > 0:
        data_len2 = data_len
    else:
        data_len2 = len(data)

    for j in range(data_len2):
        b = data[j] & 0xFF
        crc16ret ^= b << 8
        crc16ret &= 0xFFFF
        for i in range(8):
            if (crc16ret & 0x8000):
                crc16ret = (crc16ret << 1) ^ polynom
            else:
                crc16ret = crc16ret << 1
            crc16ret &= 0xFFFF
    crc_hi = (crc16ret >> 8) & 0xFF
    crc_lo = crc16ret & 0xFF
    return [crc_hi, crc_lo]


def crc16_check(data):
    i = len(data)
    (crc_hi, crc_lo) = crc16(data, i - 2)
    return (data[i - 1] == crc_lo) and (data[i - 2] == crc_hi)


def crc16_append(data):
    (crc_hi, crc_lo) = crc16(data)
    return data + bytearray([crc_hi, crc_lo])


class NeptunSocket:

    def __init__(self, owner, type=socket.SOCK_STREAM, port=SERVER_PORT):
        self.owner = owner
        self.sock = None
        self.is_udp = type == socket.SOCK_DGRAM
        self.port = port
        self.request_time = None
        self.request_data = None
        self.wait_response = False
        self.connected = False
        self._request_timeout = 0
        self.last_activity = datetime.datetime.now()
        self.prepare_socket()

    def prepare_socket(self):
        if self.sock is None:
            self.owner.log("Allocating socket")
            if self.is_udp:
                self.sock = self._prepare_socket_udp()
            else:
                self.sock = self._prepare_socket_tcp()
        return self.sock

    def _prepare_socket_tcp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(1)
        except AttributeError:
            pass
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFSIZE)
        # фикс исходного порта 6350
        sock.bind(('', self.port))
        return sock

    def _prepare_socket_udp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(1)
        except AttributeError:
            pass
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFSIZE)
        sock.bind(('', BROADCAST_PORT))
        return sock

    def _set_keepalive_linux(self, after_idle_sec=1, interval_sec=3, max_fails=5):
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)

    def _set_keepalive_windows(self, after_idle_sec=1, interval_sec=3, max_fails=5):
        self.sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, interval_sec * (max_fails + 1) * 1000, interval_sec * 1000))

    def _connect(self, address):
        if self.is_udp:
            self.connected = True
            return True

        self.owner.log("Connecting to:", address)
        if self.sock is None:
            self.prepare_socket()

        _error = "Unable to connect"
        try:
            res = self.sock.connect_ex(address)
            if res == 0:
                self.owner.log("Connected successfully to:", address)
                self.connected = True
            else:
                self.owner.log(_error, res)
            self.last_activity = datetime.datetime.now()

            # ВАЖНО: убрали send_reconnect() сразу после коннекта — он вызывал ответ FE (BUSY)

            if not self.is_udp:
                if (os.name == "posix"):
                    self._set_keepalive_linux(1, 3, 3)
                else:
                    self._set_keepalive_windows(1, 3, 3)

        except Exception as e:
            self.owner.log_traceback(_error, e)
            self.disconnect()
        except:
            self.owner.log(_error)
            self.disconnect()

        return self.connected

    def disconnect(self):
        if self.connected:
            self.owner.log("Closing connection")
        self.connected = False

        _error = "Unable to close connection"
        try:
            self.owner.log("Shutdowning socket")
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except:
                pass
            self.owner.log("Closing socket")
            if hasattr(self.sock, '_sock'):
                self.sock._sock.close()
            self.sock.close()
        except Exception as e:
            self.owner.log_traceback(_error, e)
        except:
            self.owner.log(_error)
        self.sock = None

    def request_send(self, data, addr, port, timeout):
        self.request_time = datetime.datetime.now()
        self.last_activity = self.request_time
        self.request_data = data
        self._request_timeout = timeout
        self.wait_response = timeout > 0
        if not self.connected:
            self._connect((addr, port))
        if self.connected:
            if self.owner.debug_mode > 1:
                self.owner.log("--> (" + addr + ':' + str(port) + "):", self.owner._formatBuffer(data))

            if self.is_udp:
                self.sock.sendto(data, (addr, port))
            else:
                res = self.sock.send(data)
                if res <= 0:
                    self.owner.log("Unable to send TCP data")

    def request_check_timeout(self):
        if self.request_time is not None:
            self.last_activity = datetime.datetime.now()
            diff = time_delta(self.request_time)
            return diff >= self._request_timeout
        else:
            return True

    def request_complete(self):
        self.request_time = None
        self.request_data = None
        self.wait_response = False

    def check_close_conn(self):
        if (not self.is_udp) and self.connected:
            diff = time_delta(self.last_activity)
            if diff >= 120:
                self.disconnect()


class RequestSendPeriodically:
    def __init__(self, owner, timeout, method):
        self.owner = owner
        self.timeout = timeout
        self.method = method
        self.last_sent = None
        self.retry = 0
        self.count = 0

    def check_send(self, timeout=None, incCounter=True):
        if self.owner.socket is None:
            return False

        if self.owner.socket.wait_response:
            return False

        timeout_ = self.timeout if timeout is None else timeout
        diff = (self.timeout + 1) if (self.last_sent is None) else time_delta(self.last_sent)

        if diff >= timeout_:
            self.last_sent = datetime.datetime.now()
            self.method()
            if incCounter:
                self.count += 1
            return True
        return False


class NeptunConnector(threading.Thread):
    SEND_WHOIS_TIMEOUT = 300
    SEND_HEARTBEAT_TIMEOUT = 300

    def __init__(self, ip, port=SERVER_PORT, data_callback=None, log_callback=None, debug_mode=0):
        self.ip = ip
        self.port = port
        self.debug_mode = debug_mode
        self.log_callback = log_callback
        self.data_callback = data_callback

        self.whois_request = RequestSendPeriodically(self, NeptunConnector.SEND_WHOIS_TIMEOUT, self.send_whois)

        self.command_queue = queue.Queue()
        self.device = {'lines': {}}
        self.terminated = False
        self.socket = None

        self.command_signal = 0
        self.last_state_updated = None
        self.state_update_interval = 120

        self.log_prefix = '[' + ip + ']:'

        # буфер TCP и признаки цепочки
        self._rxbuf = bytearray()
        self.got_counter_names = False

        # «ожидаемый» ответ (для ретраев)
        self._pending = None
        self._pending_sent = None
        self._pending_retries = 0
        self._pending_retry_timeout = 1.0
        self._pending_max_retries = 5

        threading.Thread.__init__(self)

    def terminate(self):
        self.terminated = True
        self.command_queue.put(None)

    def run(self):
        self.log('Thread started')

        if self.ip == BROADCAST_ADDRESS:
            self.socket = NeptunSocket(self, socket.SOCK_DGRAM, self.port)
        else:
            self.socket = NeptunSocket(self, port=self.port)

        while not self.terminated:
            try:
                self.check_incoming()
            except Exception as e:
                if self.debug_mode > 1:
                    self.log_traceback("Error in connector's thread", e)
            time.sleep(0.5)

        if self.socket is not None:
            self.socket.disconnect()

        self.log('Thread terminated')

    def _formatBuffer(self, data: bytes):
        res = ""
        cnt = 0
        for n in data:
            res += format(n, '02X') + ' '
            cnt += 1
            if cnt >= 32:
                cnt = 0
                res += "\n"
        return res

    def _update_timestamp(self, *args):
        dt = datetime.datetime.now()
        dt = dt.replace(microsecond=0)
        self.device['timestamp'] = dt.isoformat(' ')

    def log(self, *args):
        if self.log_callback is not None:
            self.log_callback(self.log_prefix, *args)
        else:
            d = datetime.datetime.now()
            print(self.log_prefix, d.strftime("%Y-%m-%d %H:%M:%S"), *args)
        return

    def log_traceback(self, message, ex, ex_traceback=None):
        if self.debug_mode:
            if ex_traceback is None:
                ex_traceback = ex.__traceback__
            tb_lines = [line.rstrip('\n') for line in
                        traceback.format_exception(ex.__class__, ex, ex_traceback)]
            self.log(message + ':', tb_lines)
        else:
            self.log(message + ':', ex)
        return

    def get_line_info(self, idx):
        line_id = 'line' + str(idx)
        if line_id not in self.device['lines']:
            self.device['lines'][line_id] = {}
        return self.device['lines'][line_id]

    def set_line_info(self, idx, info):
        line_id = 'line' + str(idx)
        self.device['lines'][line_id] = info

    def decode_status(self, status):
        if status == 0x00:
            return 'NORMAL'
        s = []
        if status & 0x01:
            s.append('ALARM')
        if status & 0x02:
            s.append('MAIN BATTERY')
        if status & 0x04:
            s.append('SENSOR BATTERY')
        if status & 0x08:
            s.append('SENSOR OFFLINE')
        return ','.join(s)

    # ------------------- Pending / Retry helpers -------------------

    def _set_pending(self, pkt_type, retry_timeout=1.0):
        self._pending = pkt_type
        self._pending_sent = datetime.datetime.now()
        self._pending_retries = 0
        self._pending_retry_timeout = retry_timeout

    def _clear_pending(self):
        self._pending = None
        self._pending_sent = None
        self._pending_retries = 0

    def _retry_pending_if_needed(self):
        if self._pending is None or self._pending_sent is None:
            return
        if time_delta(self._pending_sent) < self._pending_retry_timeout:
            return
        if self._pending_retries >= self._pending_max_retries:
            self.log('Too many retries, giving up pending request')
            self._clear_pending()
            return

        self._pending_retries += 1
        self.log(f"Retry {self._pending_retries}/{self._pending_max_retries} for pending packet 0x{self._pending:02X}")

        if self._pending == PACKET_COUNTER_NAME:
            self._raw_send_counter_names()
        elif self._pending == PACKET_COUNTER_STATE:
            self._raw_send_counter_value()
        elif self._pending == PACKET_SENSOR_NAME:
            self._raw_send_sensor_names()
        elif self._pending == PACKET_SENSOR_STATE:
            self._raw_send_sensor_state()
        else:
            self._clear_pending()
            return

        # экспоненциальный backoff (до 8 секунд)
        self._pending_retry_timeout = min(self._pending_retry_timeout * 2.0, 8.0)
        self._pending_sent = datetime.datetime.now()

    # ------------------- TCP framing by explicit length -------------------

    def _process_rxbuf(self, sock):
        """
        Разбор TCP-потока по полю длины.
        Кадр: 0x02 0x54 <dir> <type> <len_hi> <len_lo> <payload> <crc_hi> <crc_lo>
        """
        START2 = b'\x02\x54'

        while True:
            i = self._rxbuf.find(START2)
            if i == -1:
                if len(self._rxbuf) > 1:
                    del self._rxbuf[:-1]
                break

            if i > 0:
                del self._rxbuf[:i]

            if len(self._rxbuf) < 6:
                break

            payload_len = (self._rxbuf[4] << 8) | self._rxbuf[5]
            total_len = 6 + payload_len + 2  # header + payload + CRC

            if len(self._rxbuf) < total_len:
                break

            frame = bytes(self._rxbuf[:total_len])
            del self._rxbuf[:total_len]

            try:
                if not crc16_check(frame):
                    self.log("Invalid checksum of a data packet")
                    continue
                self.handle_incoming_data(sock, self.ip, frame)
            except Exception as e:
                self.log_traceback('Unhandled exception in frame handler', e)

    # ------------------- IO loop -------------------

    def check_incoming(self):
        if self.socket is None:
            return

        if self.socket.wait_response:
            if self.socket.request_check_timeout():
                self.log('Request timeout')
                self.socket.request_complete()
                self.socket.disconnect()
        else:
            self.send_from_queue()

        self.socket.check_close_conn()

        try:
            if self.socket.connected:
                if self.socket.is_udp:
                    data, addr = self.socket.sock.recvfrom(SOCKET_BUFSIZE)
                    if data:
                        if self.debug_mode > 1:
                            self.log('<--', addr[0], ":", self._formatBuffer(data))
                        self.handle_incoming_data(self.socket, addr[0], data)
                else:
                    data = self.socket.sock.recv(SOCKET_BUFSIZE)
                    if not data:
                        # даже если данных нет — проверим ретраи pending
                        self._retry_pending_if_needed()
                        return True
                    if self.debug_mode > 1:
                        self.log('<--', self.ip, ":", self._formatBuffer(data))
                    self._rxbuf += data
                    self._process_rxbuf(self.socket)

            # проверяем ретраи после обработки
            self._retry_pending_if_needed()
            return True

        except socket.timeout:
            self._retry_pending_if_needed()

        except socket.error as e:
            if e.errno == errno.ECONNRESET:
                self.log("Disconnected by peer (%r)" % (e,))
                self.socket.disconnect()
            else:
                self.log("Other socket error (%r)" % (e,))

        except Exception as e:
            self.log_traceback("Can't incoming data %r" % (data if 'data' in locals() else None), e)
            raise

    # ------------------- Decoder -------------------

    def handle_incoming_data(self, sock, ip, data):
        """
        Handle an incoming data packet (control checksum, decode to a readable format)
        """
        if not crc16_check(data):
            self.log("Invalid checksum of a data packet")
            return False

        callback_data = {}
        if sock.is_udp:
            if (data == sock.request_data):
                return False

        try:
            if sock.wait_response:
                sock.wait_response = False
                sock.request_data = None
                sock.request_time = None

            if self.data_callback is not None:
                data = bytearray(data)
                data_len = len(data) - 2
                del data[data_len:]  # remove CRC
                packet_type = data[3]

                callback_data['type'] = packet_type

                if sock.is_udp:
                    callback_data['ip'] = ip
                    if packet_type == PACKET_WHOIS:
                        offset = 6
                        callback_data['type'] = chr(data[offset]) + chr(data[offset+1])
                        offset += 2
                        callback_data['version'] = chr(data[offset]) + '.' + \
                            chr(data[offset+1]) + '.' + chr(data[offset+2])
                        offset += 3
                        data = data.split(b':', 2)
                        data = data[1]
                        callback_data['mac'] = data

                elif packet_type == PACKET_SYSTEM_STATE:
                    # system state
                    self.device['lines'] = {}
                    offset = 6
                    while offset < data_len:
                        tag = data[offset]
                        offset += 1
                        tag_size = data[offset] * 0x100 + data[offset + 1]
                        offset += 2
                        offset2 = offset
                        if tag == 73:  # 0x49
                            self.device['type'] = chr(data[offset2]) + chr(data[offset2+1])
                            offset2 += 2
                            self.device['version'] = chr(data[offset2]) + '.' + \
                                chr(data[offset2+1]) + '.' + chr(data[offset2+2])
                        elif tag == 78:  # 0x4E
                            str_data = data[offset2:offset2+tag_size]
                            self.device['name'] = str_data.decode('ascii')
                        elif tag == 77:  # 0x4D
                            str_data = data[offset2:offset2+tag_size]
                            self.device['mac'] = str_data.decode('ascii')
                        elif tag == 65:  # 0x41
                            access = (tag_size > 0) and (data[offset2] > 0)
                            self.device['access'] = access
                        elif tag == 83:  # 0x53
                            self._update_timestamp()
                            self.device['valve_state_open'] = data[offset2] == 1
                            offset2 += 1
                            self.device['sensor_count'] = data[offset2]
                            offset2 += 1
                            self.device['relay_count'] = data[offset2]
                            offset2 += 1
                            self.device['flag_dry'] = data[offset2] == 1
                            offset2 += 1
                            self.device['flag_cl_valve'] = data[offset2] == 1
                            offset2 += 1
                            self.device['line_in_config'] = data[offset2]
                            offset2 += 1
                            self.device['status'] = data[offset2]
                            self.device['status_name'] = self.decode_status(data[offset2])
                        elif tag == 115:  # 0x73
                            # wired lines state
                            for idx in range(4):
                                sensor_info = self.get_line_info(idx)
                                sensor_info['state'] = data[offset2]
                                self.set_line_info(idx, sensor_info)
                                offset2 += 1
                        offset += tag_size

                    # маленькая пауза перед стартом цепочки и запуск с pending
                    try:
                        time.sleep(0.2)
                    except:
                        pass
                    self.got_counter_names = False
                    self._send_with_pending(PACKET_COUNTER_NAME, self._raw_send_counter_names, retry_timeout=1.0)

                elif packet_type == PACKET_COUNTER_NAME:
                    self._clear_pending()
                    self.got_counter_names = True
                    offset = 4
                    tag_size = data[offset] * 0x100 + data[offset + 1]
                    offset += 2
                    str_data = data[offset:]
                    sensor_names = str_data.split(b'\x00')
                    if len(sensor_names) and sensor_names[-1] == b'':
                        sensor_names.pop(-1)
                    idx = 0
                    mode = self.device.get('line_in_config', 0)
                    mask = 1
                    for sensor_name in sensor_names:
                        if (mode & mask) != 0:
                            line_type = 'counter'
                        else:
                            line_type = 'sensor'
                        sensor_info = self.get_line_info(idx)
                        sensor_info['name'] = sensor_name.decode('cp1251')
                        sensor_info['type'] = line_type
                        sensor_info['wire'] = True
                        self.set_line_info(idx, sensor_info)
                        idx += 1

                    self._send_with_pending(PACKET_COUNTER_STATE, self._raw_send_counter_value, retry_timeout=1.0)

                elif packet_type == PACKET_COUNTER_STATE:
                    self._clear_pending()
                    offset = 4
                    tag_size = data[offset] * 0x100 + data[offset + 1]
                    offset += 2

                    idx = 0
                    while offset < data_len:
                        sensor_info = self.get_line_info(idx)
                        value = (data[offset]   << 24) + \
                                (data[offset+1] << 16) + \
                                (data[offset+2] <<  8) + \
                                (data[offset+3])
                        sensor_info['value'] = value
                        sensor_info['step'] = data[offset + 4]
                        self.set_line_info(idx, sensor_info)
                        offset += 5
                        idx += 1

                    self._send_with_pending(PACKET_SENSOR_NAME, self._raw_send_sensor_names, retry_timeout=1.0)

                elif packet_type == PACKET_SENSOR_NAME:
                    self._clear_pending()
                    offset = 4
                    tag_size = data[offset] * 0x100 + data[offset + 1]
                    offset += 2
                    str_data = data[offset:]
                    sensor_names = str_data.split(b'\x00')
                    if len(sensor_names) and sensor_names[-1] == b'':
                        sensor_names.pop(-1)
                    idx = 4
                    for sensor_name in sensor_names:
                        sensor_info = self.get_line_info(idx)
                        sensor_info['name'] = sensor_name.decode('cp1251')
                        sensor_info['type'] = 'sensor'
                        sensor_info['wire'] = False
                        self.set_line_info(idx, sensor_info)
                        idx += 1

                    self._send_with_pending(PACKET_SENSOR_STATE, self._raw_send_sensor_state, retry_timeout=1.0)

                elif packet_type == PACKET_SENSOR_STATE:
                    self._clear_pending()
                    self.last_state_updated = datetime.datetime.now()
                    offset = 4
                    tag_size = data[offset] * 0x100 + data[offset + 1]
                    offset += 2

                    idx = 4
                    while offset < data_len:
                        sensor_info = self.get_line_info(idx)
                        sensor_info['signal'] = data[offset]
                        sensor_info['line'] = data[offset + 1]
                        sensor_info['battery'] = data[offset + 2]
                        sensor_info['state'] = data[offset + 3]
                        self.set_line_info(idx, sensor_info)
                        offset += 4
                        idx += 1

                elif packet_type == PACKET_BACK_STATE:
                    offset = 4
                    tag_size = data[offset] * 0x100 + data[offset + 1]
                    offset += 2
                    if tag_size > 0:
                        self._update_timestamp()
                        self.device['status'] = data[offset]
                        self.device['status_name'] = self.decode_status(data[offset])

                elif packet_type == PACKET_ACK:
                    # Просто keepalive — мягко подождём и, если есть pending, повторим по таймеру
                    pass

                elif packet_type == PACKET_BUSY:
                    # устройство занято — ретраи обработает _retry_pending_if_needed()
                    self.log("Device returned BUSY (0xFE), will retry pending shortly")

                try:
                    self.data_callback(self, sock, ip, callback_data)
                except Exception as e:
                    self.log_traceback('Unhandled exception id data_callback', e)

        except Exception as e:
            self.log_traceback('Unhandled exception', e)

        return True

    # ------------------- Очередь отправки -------------------

    def send_from_queue(self):
        command = None
        try:
            if not self.command_queue.empty():
                command = self.command_queue.get_nowait()
        except:
            pass

        if command is not None:
            _error = 'Unable to process command'
            try:
                data = command['data']
                ip = command['ip']
                port = command['port']
                timeout = command['timeout']

                self.socket.request_send(data, ip, port, timeout)

            except Exception as e:
                self.log_traceback(_error, e)
            except:
                self.log(_error)

            self.command_queue.task_done()

    def send_command(self, data, ip, port, timeout):
        self.log("++Q (" + ip + ':' + str(port) + ") :", data)
        self.command_queue.put({'data': data, 'ip': ip, 'port': port, 'timeout': timeout})

    # ------------------- НИЗКОУРОВНЕВЫЕ (“raw”) -------------------

    def _raw_send_counter_names(self):
        data = bytearray([2, 84, 81, PACKET_COUNTER_NAME, 0, 0])
        data = crc16_append(data)
        self.send_command(data, self.ip, self.port, 5)

    def _raw_send_counter_value(self):
        data = bytearray([2, 84, 81, PACKET_COUNTER_STATE, 0, 0])
        data = crc16_append(data)
        self.send_command(data, self.ip, self.port, 5)

    def _raw_send_sensor_names(self):
        data = bytearray([2, 84, 81, PACKET_SENSOR_NAME, 0, 0])
        data = crc16_append(data)
        self.send_command(data, self.ip, self.port, 5)

    def _raw_send_sensor_state(self):
        data = bytearray([2, 84, 81, PACKET_SENSOR_STATE, 0, 0])
        data = crc16_append(data)
        self.send_command(data, self.ip, self.port, 5)

    # ------------------- ВЫСОКОУРОВНЕВЫЕ (с pending) -------------------

    def _send_with_pending(self, pkt_type, builder_fn, retry_timeout=1.0):
        builder_fn()
        self._set_pending(pkt_type, retry_timeout)

    # ------------------- Публичные методы -------------------

    def send_whois(self):
        data = bytearray([2, 84, 81, PACKET_WHOIS, 0, 0])
        data = crc16_append(data)
        self.whois_request.last_sent = datetime.datetime.now()
        self.send_command(data, BROADCAST_ADDRESS, BROADCAST_PORT, 0)
        return self

    def send_reconnect(self):
        """
        Держим для совместимости, но больше НЕ вызываем автоматически.
        """
        data = bytearray([2, 84, 81, PACKET_RECONNECT, 0, 3, 82])
        data = crc16_append(data)
        self.send_command(data, self.ip, self.port, 0)
        return self

    def send_get_counter_names(self):
        self._send_with_pending(PACKET_COUNTER_NAME, self._raw_send_counter_names, retry_timeout=1.0)
        return self

    def send_get_counter_value(self):
        self._send_with_pending(PACKET_COUNTER_STATE, self._raw_send_counter_value, retry_timeout=1.0)
        return self

    def send_get_sensor_names(self):
        self._send_with_pending(PACKET_SENSOR_NAME, self._raw_send_sensor_names, retry_timeout=1.0)
        return self

    def send_get_sensor_state(self):
        self._send_with_pending(PACKET_SENSOR_STATE, self._raw_send_sensor_state, retry_timeout=1.0)
        return self

    def send_get_system_state(self):
        """
        Get detailed device info and wired sensors state.
        """
        data = bytearray([2, 84, 81, PACKET_SYSTEM_STATE, 0, 0])
        data = crc16_append(data)
        self.send_command(data, self.ip, self.port, 30)  # увеличенный таймаут
        # SYSTEM_STATE не кладём в pending — ответ приходит сразу, далее начнётся цепочка
        return self

    def send_get_background_status(self):
        data = bytearray([2, 84, 81, PACKET_BACK_STATE, 0, 0])
        data = crc16_append(data)
        self.send_command(data, self.ip, self.port, 30)
        return self

    def send_settings(self, valve_state_open, flag_dry, flag_cl_valve, line_in_config):
        """
        Change device status bits.
        valve_state_open - valve is opened/closed.
        flag_dry - cleaning flag.
        flag_cl_valve - close a valve if wireless sensor(s) is offline.
        line_in_config - (bitmask) mode of wired sensors (1 - counter, 0 - sensor).
        """
        data = bytearray([2, 84, 81, PACKET_SET_SYSTEM_STATE, 0, 7, 83, 0, 4, 0, 0, 0, 0])
        if valve_state_open:
            data[9] = 1
        if flag_dry:
            data[10] = 1
        if flag_cl_valve:
            data[11] = 1
        data[12] = line_in_config
        data = crc16_append(data)
        self.send_command(data, self.ip, self.port, 5)
        return self

    def send_set_valve_state(self, is_open):
        self.send_settings(is_open, self.device.get('flag_dry', False),
                           self.device.get('flag_cl_valve', False), self.device.get('line_in_config', 0))
        return self

    def send_set_cleaning_mode(self, is_enabled):
        self.send_settings(self.device.get('valve_state_open', False), is_enabled,
                           self.device.get('flag_cl_valve', False), self.device.get('line_in_config', 0))
        return self
