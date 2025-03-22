#![allow(unused)]

use core::net::Ipv4Addr;
use std::mem::{size_of, transmute};
use windows::Win32::Networking::WinSock::*;

const PACKET: &[u8; 4] = b"asdf";
const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const WSL: Ipv4Addr = Ipv4Addr::new(172, 30, 104, 9);

#[repr(C)]
struct IcmpHeder {
    icmp_type: u8,
    icmp_code: u8,
    icmp_checksum: u16,
    icmp_id: u16,
    icmp_sequence: u16,
}

unsafe fn checksum(data: *const u16, len: usize) -> u16 {
    let mut sum = 0;
    let mut i = 0;

    unsafe {
        while i < len {
            sum += *data.add(i) as u32;
            i += 1;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    return !sum as u16;
}

// returns a byte vector containing a complete ICMP packet
unsafe fn make_packet(header: &mut IcmpHeder, message: &[u8]) -> Vec<u8> {
    unsafe {
        let mut cs_v = Vec::<u8>::new();
        let header_ptr = transmute::<*const IcmpHeder, *const u8>(header as *const IcmpHeder);

        for i in 0..8 {
            cs_v.push(*header_ptr.add(i));
        }

        let mut size: usize = size_of::<IcmpHeder>();
        size += message.len();
        if size % 2 != 0 {
            size += 1;
            cs_v.push(0);
        }

        cs_v.extend_from_slice(&message);

        let packet_ptr = transmute::<*const u8, *const u16>(cs_v.as_ptr());

        header.icmp_checksum = checksum(packet_ptr, size / 2);

        let mut v = Vec::<u8>::new();
        for i in 0..8 {
            v.push(*header_ptr.add(i));
        }

        v.extend_from_slice(&message);

        return v;
    }
}

#[test]
fn ip_header() {
    let header =
        etherparse::Ipv4Header::new(4, 5, etherparse::IpNumber::ICMP, [0, 0, 0, 0], [0, 0, 0, 0]);
    let h = header.unwrap();
    let bytes = h.to_bytes();
    panic!("{:?}", bytes);
}

#[test]
fn test_checksum() {
    use windows::Win32::System::Threading::GetCurrentProcessId;

    unsafe {
        let mut size: usize = size_of::<IcmpHeder>();
        assert!(size % 2 == 0);
        assert!(size == 8);

        let header = IcmpHeder {
            icmp_type: 8,
            icmp_code: 0,
            icmp_checksum: 0,
            icmp_id: GetCurrentProcessId() as u16,
            icmp_sequence: 1,
        };

        let message: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
        size += message.len();

        if size % 2 != 0 {
            size += 1;
        }

        let mut v = Vec::<u8>::with_capacity(size);
        let header_ptr = transmute::<*const IcmpHeder, *const u8>(&header as *const IcmpHeder);

        let mut i = 0;
        while i < size_of::<IcmpHeder>() {
            v.push(*header_ptr.add(i));
            i += 1;
        }

        v.extend_from_slice(&message);

        let packet_ptr = transmute::<*const u8, *const u16>(v.as_ptr());
        let cs = checksum(packet_ptr, size / 2);
        panic!("Checksum: 0x{:X}", cs);
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

        let s = socket(AF_INET.0.into(), SOCK_RAW, IPPROTO_ICMP.0);
        if s.is_err() {
            panic!(
                "socket failed with code 0x{:X} and error {}",
                WSAGetLastError().0,
                s.unwrap_err()
            );
        } else {
            println!("socket succeeded");
        }

        let mut sock_addr = SOCKADDR_IN::default();
        sock_addr.sin_addr = IN_ADDR::from(WSL);
        sock_addr.sin_family = AF_INET;

        let r = sendto(
            s.unwrap(),
            PACKET,
            0,
            transmute::<&SOCKADDR_IN, *mut SOCKADDR>(&sock_addr),
            size_of::<SOCKADDR_IN>() as i32,
        );
        if r != PACKET.len() as i32 {
            panic!(
                "sendto failed with code 0x{:X} and error {}",
                WSAGetLastError().0,
                r
            );
        } else {
            println!("sendto succeeded");
        }
    }

    println!("Hello, world!");
}
