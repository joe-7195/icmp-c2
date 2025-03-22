#![allow(unused, dead_code)]

use core::net::Ipv4Addr;
use std::io::Empty;
use etherparse::err::ipv4;
use etherparse::*;
use std::mem::transmute;
use windows::Win32::Networking::WinSock::*;
use windows::Win32::System::Threading::GetCurrentProcessId;

const WSL: [u8; 4] = [172, 30, 104, 9];
const WIN: [u8; 4] = [172, 30, 96, 1];

fn make_packet(payload: &[u8]) -> Vec<u8> {
    unsafe {
        let pid = GetCurrentProcessId() as u16;

        let header = Icmpv4Header::with_checksum(
            Icmpv4Type::EchoRequest(IcmpEchoHeader { id: pid, seq: 0 }),
            payload,
        );

        let mut res = Vec::<u8>::with_capacity(Icmpv4Header::MAX_LEN + payload.len());

        match header.write(&mut res) {
            Ok(_) => {}
            Err(e) => panic!("Failed to write ICMP header: {}", e),
        }

        res.extend_from_slice(payload);

        return res;
    }
}

fn main() {
    unsafe {
        let mut wsa_data = WSADATA::default();

        let res = WSAStartup(0x0202, &mut wsa_data);
        if res != 0 {
            panic!("WSAStartup failed with code 0x{:X}", res);
        } else {
            println!("WSAStartup succeeded");
        }

        let s = match socket(AF_INET.0.into(), SOCK_RAW, IPPROTO_ICMP.0) {
            Ok(s) => s,
            Err(e) => panic!(
                "socket failed with code 0x{:X} and error {}",
                WSAGetLastError().0,
                e
            ),
        };

        let mut sock_addr = SOCKADDR_IN::default();
        sock_addr.sin_addr = IN_ADDR::from(Ipv4Addr::from(WSL));
        sock_addr.sin_family = AF_INET;

        let packet = make_packet(&[0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48]);

        let r = sendto(
            s,
            packet.as_slice(),
            0,
            transmute::<&SOCKADDR_IN, *const SOCKADDR>(&sock_addr),
            size_of::<SOCKADDR_IN>() as i32,
        );
        if r != packet.len() as i32 {
            panic!(
                "sendto failed with code 0x{:X} and error {}",
                WSAGetLastError().0,
                r
            );
        } else {
            println!("sendto succeeded");
        }

        let mut buffer = [0u8; 256];
        let r = recv(s, &mut buffer, SEND_RECV_FLAGS(0));

        if r == SOCKET_ERROR {
            panic!(
                "recv failed with code 0x{:X} and error {}",
                WSAGetLastError().0,
                r
            );
        } else {
            println!("recv succeeded buffer: {:X?}", &buffer[..r as usize]);
        }

        let packet = match PacketHeaders::from_ip_slice(&buffer[..r as usize]) {
            Ok(ph) => ph,
            Err(e) => panic!("failed to parse packet: {}", e),
        };

        println!("Parsed packet: {:?}", packet);
        let payload = match packet.payload {
            PayloadSlice::Icmpv4(pl) => pl,
            PayloadSlice::Empty => panic!("no payload found"),
            _ => panic!("malformed payload found (not ICMPv4)"),
        };

        println!("Payload: {:?} as string: {}", payload, String::from_utf8_lossy(payload));
    }
}
