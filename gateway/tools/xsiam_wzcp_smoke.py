#!/usr/bin/env python3
import argparse
import socket
import struct
import time

MAGIC = 0x575A4350
VERSION = 1
HEADER_SIZE = 32

MSG_HELLO = 1
MSG_EVENT_BATCH = 2
MSG_ACK = 3
MSG_HEARTBEAT = 4


def build_frame(msg_type, agent_id, seq, body=b""):
    header = struct.pack(
        "!IBBBBIQQI",
        MAGIC,
        VERSION,
        HEADER_SIZE,
        0,
        msg_type,
        agent_id,
        seq,
        int(time.time() * 1000),
        len(body),
    )
    return struct.pack("!I", len(header) + len(body)) + header + body


def build_hello(agent_id, agent_name, agent_version, host_type, mac_addresses):
    body = struct.pack("!HH", 2, 0)
    for item in (agent_id.encode(), agent_name.encode(), agent_version.encode(), host_type.encode()):
        body += struct.pack("!H", len(item)) + item
    body += struct.pack("!H", len(mac_addresses))
    for mac in mac_addresses:
        item = mac.encode()
        body += struct.pack("!H", len(item)) + item
    return body


def build_event(payload):
    data = payload.encode()
    return struct.pack(
        "!HBBQQH",
        1,
        1,
        0,
        int(time.time() * 1000),
        1001,
        len(data),
    ) + data


def recv_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        data = sock.recv(size - len(chunks))
        if not data:
            raise RuntimeError("connection closed")
        chunks.extend(data)
    return bytes(chunks)


def recv_frame(sock):
    frame_len = struct.unpack("!I", recv_exact(sock, 4))[0]
    data = recv_exact(sock, frame_len)
    header = struct.unpack("!IBBBBIQQI", data[:HEADER_SIZE])
    return {
        "magic": header[0],
        "version": header[1],
        "header_len": header[2],
        "flags": header[3],
        "msg_type": header[4],
        "agent_id": header[5],
        "seq": header[6],
        "timestamp_ms": header[7],
        "body_len": header[8],
        "body": data[HEADER_SIZE:],
    }


def send_ack(sock, agent_id, frame):
    body = struct.pack("!Q", frame["seq"])
    sock.sendall(build_frame(MSG_ACK, agent_id, frame["seq"], body))


def main():
    parser = argparse.ArgumentParser(description="WZCP gateway smoke test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1514)
    parser.add_argument("--agent-id", type=int, default=1)
    parser.add_argument("--agent-key", default=None)
    parser.add_argument("--agent-name", default="wzcp-smoke-agent")
    parser.add_argument("--agent-version", default="4.14.5-xsiam")
    parser.add_argument("--host-type", choices=("pc", "server"), default="pc")
    parser.add_argument("--mac-address", action="append", default=[])
    parser.add_argument("--payload", default="wzcp smoke event no json")
    parser.add_argument("--wait-heartbeat", action="store_true")
    parser.add_argument("--hold-seconds", type=float, default=0)
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        agent_key = args.agent_key or str(args.agent_id)
        sock.sendall(
            build_frame(
                MSG_HELLO,
                args.agent_id,
                1,
                build_hello(agent_key, args.agent_name, args.agent_version,
                            args.host_type, args.mac_address),
            )
        )
        hello_ack = recv_frame(sock)
        print(f"hello_ack type={hello_ack['msg_type']} seq={hello_ack['seq']} body_len={hello_ack['body_len']}")

        sock.sendall(build_frame(MSG_EVENT_BATCH, args.agent_id, 2, build_event(args.payload)))
        event_ack = recv_frame(sock)
        print(f"event_ack type={event_ack['msg_type']} seq={event_ack['seq']} body_len={event_ack['body_len']}")

        if args.wait_heartbeat:
            sock.settimeout(35)
            heartbeat = recv_frame(sock)
            print(f"heartbeat type={heartbeat['msg_type']} seq={heartbeat['seq']} body_len={heartbeat['body_len']}")
            if heartbeat["msg_type"] != MSG_HEARTBEAT:
                raise RuntimeError("expected heartbeat")
            send_ack(sock, args.agent_id, heartbeat)

        if args.hold_seconds > 0:
            time.sleep(args.hold_seconds)


if __name__ == "__main__":
    main()
