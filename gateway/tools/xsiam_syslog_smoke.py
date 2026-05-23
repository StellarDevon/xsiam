#!/usr/bin/env python3
import argparse
import socket
import time


def main():
    parser = argparse.ArgumentParser(description="TCP syslog smoke test for xsiam_agent listener")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1514)
    parser.add_argument("--message", default="<134>1 2026-05-23T09:00:00Z fw01 vendor - - - test syslog event")
    parser.add_argument("--hold-seconds", type=float, default=0)
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        sock.sendall((args.message + "\n").encode())
        if args.hold_seconds > 0:
            time.sleep(args.hold_seconds)


if __name__ == "__main__":
    main()
