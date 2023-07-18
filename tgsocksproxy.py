#!/usr/bin/env python3

import asyncio
import struct
import socket
import urllib.parse
import urllib.request
import collections
import time

from config import PORT, USERS

BLOCK_NON_TG_HOSTS = True
HIDE_ERRORS_BEFORE_AUTH = True

# all networks are /22
TG_NETWORKS = {
    "91.108.4.0", "91.108.8.0", "91.108.12.0", "91.108.16.0", "91.108.56.0",
    "149.154.160.0", "149.154.164.0", "149.154.168.0", "149.154.172.0"
}

STATS_PRINT_PERIOD = 600

PRINT_TG_INFO = True

READ_BUF_SIZE = 4096

IPV4_ADDR_LEN = 4
IPV6_ADDR_LEN = 16

BAD_IPV4_ADDR = b"\x00\x00\x00\x00"
BAD_PORT = b"\x00\x00"

# Consts from RFC1928
SOCKS5_VERSION = b"\x05"
SUBNEGOTIATION_VERSION = b"\x01"

USERNAME_PASSWORD_METHOD = b"\x02"
NO_ACCEPTABLE_METHODS = b"\xff"

STATUS_SUCCESS = b"\x00"
STATUS_FAIL = b"\x01"

CMD_CONNECT = b"\x01"

ADDR_IPV4 = b"\x01"
ADDR_DOMAINNAME = b"\x03"
ADDR_IPV6 = b"\x04"

REPLY_SUCCEEDED = b"\x00"
REPLY_GENERAL_FAILURE = b"\x01"
REPLY_NOT_ALOWED = b"\x02"
REPLY_REFUSED = b"\x05"
REPLY_CMD_NOT_SUPPORTED = b"\x07"
REPLY_ADDR_TYPE_NOT_SUPPORTED = b"\x08"

RESERVED = b"\x00"


def validate_addr(addr, addr_type):
    if BLOCK_NON_TG_HOSTS:
        if addr_type != ADDR_IPV4:
            return False

        ip_net = list(struct.unpack("!BBBB", addr))

        # calc /22
        ip_net[2] = ip_net[2] & 0xfc
        ip_net[3] = 0
        net_addr = ".".join(map(str, ip_net))
        if net_addr not in TG_NETWORKS:
            return False

    return True


def init_stats():
    global stats
    stats = {user: collections.Counter() for user in USERS}


def update_stats(user, connects=0, curr_connects_x2=0, octets=0):
    global stats

    if user not in stats:
        stats[user] = collections.Counter()

    stats[user].update(connects=connects, curr_connects_x2=curr_connects_x2,
                       octets=octets)


async def initial_handshake(reader, writer):
    socks_version = await reader.readexactly(1)
    if socks_version != SOCKS5_VERSION:
        return False

    n_methods = struct.unpack("!B", await reader.readexactly(1))[0]
    if n_methods == 0:
        return False

    methods = await reader.readexactly(n_methods)

    if USERNAME_PASSWORD_METHOD not in methods:
        if not HIDE_ERRORS_BEFORE_AUTH:
            writer.write(SOCKS5_VERSION + NO_ACCEPTABLE_METHODS)
            await writer.drain()
        return False

    # choose user/password auth method
    writer.write(SOCKS5_VERSION + USERNAME_PASSWORD_METHOD)
    return True


async def negotiate_login(reader, writer):
    subnegotiation_version = await reader.readexactly(1)

    if subnegotiation_version != SUBNEGOTIATION_VERSION:
        return ""

    user_len = struct.unpack("!B", await reader.readexactly(1))[0]
    if user_len == 0:
        return ""

    user = (await reader.readexactly(user_len)).decode(errors="ignore")

    password_len = struct.unpack("!B", await reader.readexactly(1))[0]
    if password_len == 0:
        return ""

    password = (await reader.readexactly(password_len)).decode(errors="ignore")

    if user not in USERS or password != USERS[user]:
        if not HIDE_ERRORS_BEFORE_AUTH:
            writer.write(SUBNEGOTIATION_VERSION + STATUS_FAIL)
            await writer.drain()
        return ""

    writer.write(SUBNEGOTIATION_VERSION + STATUS_SUCCESS)
    return user


async def handle_request(reader, writer):
    "Returns host and port to connect"

    def gen_reply(reply_code, fam=ADDR_IPV4, ip=BAD_IPV4_ADDR, port=BAD_PORT):
        return SOCKS5_VERSION + reply_code + RESERVED + fam + ip + port

    socks_version = await reader.readexactly(1)
    if socks_version != SOCKS5_VERSION:
        return None, None

    cmd = await reader.readexactly(1)
    if cmd != CMD_CONNECT:
        writer.write(gen_reply(REPLY_CMD_NOT_SUPPORTED))
        await writer.drain()
        return None, None

    reserved = await reader.readexactly(1)

    address_type = await reader.readexactly(1)

    if address_type == ADDR_IPV4:
        address = await reader.readexactly(IPV4_ADDR_LEN)
    elif address_type == ADDR_IPV6:
        address = await reader.readexactly(IPV6_ADDR_LEN)
    elif address_type == ADDR_DOMAINNAME:
        address_len = struct.unpack("!B", await reader.readexactly(1))[0]

        if address_len == 0:
            return None, None

        address = await reader.readexactly(address_len)
    else:
        writer.write(gen_reply(REPLY_ADDR_TYPE_NOT_SUPPORTED))
        await writer.drain()
        return None, None

    if not validate_addr(address, address_type):
        writer.write(gen_reply(REPLY_NOT_ALOWED))
        await writer.drain()
        return None, None

    if address_type == ADDR_IPV4:
        address = socket.inet_ntop(socket.AF_INET, address)
    elif address_type == ADDR_IPV6:
        address = socket.inet_ntop(socket.AF_INET6, address)

    port = struct.unpack("!H", await reader.readexactly(2))[0]

    try:
        reader_tgt, writer_tgt = await asyncio.open_connection(address, port)
    except ConnectionRefusedError as E:
        writer.write(gen_reply(REPLY_REFUSED))
        await writer.drain()
        return None, None
    except OSError as E:
        writer.write(gen_reply(REPLY_GENERAL_FAILURE))
        await writer.drain()
        return None, None

    writer.write(gen_reply(REPLY_SUCCEEDED, ADDR_IPV4,
                           BAD_IPV4_ADDR, BAD_PORT))
    await writer.drain()

    return reader_tgt, writer_tgt


async def handle_client(reader, writer):
    if not await initial_handshake(reader, writer):
        writer.close()
        return

    user = await negotiate_login(reader, writer)
    if not user:
        writer.close()
        return

    update_stats(user, connects=1)

    reader_tgt, writer_tgt = await handle_request(reader, writer)
    if reader_tgt is None or writer_tgt is None:
        writer.close()
        return

    async def connect_reader_to_writer(rd, wr, user):
        update_stats(user, curr_connects_x2=1)
        try:
            while True:
                data = await rd.read(READ_BUF_SIZE)
                if not data:
                    wr.write_eof()
                    await wr.drain()
                    wr.close()
                    return
                else:
                    update_stats(user, octets=len(data))
                    wr.write(data)
                    await wr.drain()
        except (ConnectionResetError, BrokenPipeError, OSError,
                AttributeError):
            wr.close()
        finally:
            update_stats(user, curr_connects_x2=-1)

    asyncio.ensure_future(connect_reader_to_writer(reader_tgt, writer, user))
    asyncio.ensure_future(connect_reader_to_writer(reader, writer_tgt, user))


async def handle_client_wrapper(reader, writer):
    try:
        await handle_client(reader, writer)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        writer.close()


async def stats_printer():
    global stats
    while True:
        await asyncio.sleep(STATS_PRINT_PERIOD)

        print("Stats for", time.strftime("%d.%m.%Y %H:%M:%S"))
        for user, stat in stats.items():
            print("%s: %d connects (%d current), %.2f MB" % (
                user, stat["connects"], stat["curr_connects_x2"] // 2,
                stat["octets"] / 1000000))
        print(flush=True)


def print_tg_info():
    my_ip = socket.gethostbyname(socket.gethostname())

    octets = [int(o) for o in my_ip.split(".")]

    ip_is_local = (len(octets) == 4 and (
        octets[0] in [127, 10] or
        octets[0:2] == [192, 168] or
        (octets[0] == 172 and 16 <= octets[1] <= 31)))

    if ip_is_local:
        my_ip = "YOUR_IP"

    for user in USERS:
        params = {
            "server": my_ip, "port": PORT, "user": user, "pass": USERS[user]
        }
        print("tg://socks?" + urllib.parse.urlencode(params), flush=True)


async def main():
    init_stats()

    stats_printer_task = asyncio.Task(stats_printer())
    asyncio.ensure_future(stats_printer_task)

    server = await asyncio.start_server(handle_client_wrapper, "0.0.0.0", PORT)

    try:
        async with server:
            await server.serve_forever()
    except KeyboardInterrupt:
        pass

    stats_printer_task.cancel()


if __name__ == "__main__":
    if PRINT_TG_INFO:
        print_tg_info()
    asyncio.run(main())
