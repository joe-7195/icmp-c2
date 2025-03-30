use anyhow::{Result, anyhow};
use core::net::Ipv4Addr;
use etherparse::{IcmpEchoHeader, Icmpv4Header, Icmpv4Type, PacketHeaders, PayloadSlice};
use std::mem::transmute;
use windows::Win32::Networking::WinSock::*;

const TIMEOUT: &[u8; 4] = unsafe { transmute::<&i32, &[u8; 4]>(&1000) }; // timeout in milliseconds as bytes (thank you windows-rs)
const PACKET_SIZE: usize = 0x10000; // technically the max size of an IPv4 packet but the mtu will never allow this
static mut REPLY_BUFFER: [u8; PACKET_SIZE] = [0u8; PACKET_SIZE]; // fat buffer for recieving packets

pub fn ws_startup() -> Result<WSADATA> {
    let mut wsa_data = WSADATA::default();

    unsafe {
        match WSAStartup(0x0202, &mut wsa_data) {
            0 => Ok(wsa_data),
            res => Err(anyhow!("WSAStartup failed with code {}", res)),
        }
    }
}

// construct valid ICMPv4 packet with checksum
fn make_packet(payload: Vec<u8>) -> Result<Vec<u8>> {
    let mut res = Vec::<u8>::with_capacity(Icmpv4Header::MAX_LEN + payload.len());

    let header = Icmpv4Header::with_checksum(
        Icmpv4Type::EchoRequest(IcmpEchoHeader { id: 6969, seq: 0 }),
        payload.as_slice(),
    );

    match header.write(&mut res) {
        Ok(_) => {}
        Err(e) => return Err(anyhow!("Failed to write ICMP header: {}", e)),
    }

    res.extend(payload);

    return Ok(res);
}

#[allow(static_mut_refs)]
pub fn send_and_recieve(data: Vec<u8>, destination: [u8; 4]) -> Result<Vec<u8>> {
    unsafe {
        let s = match socket(AF_INET.0.into(), SOCK_RAW, IPPROTO_ICMP.0) {
            Ok(s) => s,
            Err(e) => {
                return Err(anyhow!(
                    "socket failed with code {} and error {}",
                    WSAGetLastError().0,
                    e
                ));
            }
        };

        match setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, Some(TIMEOUT)) {
            SOCKET_ERROR => {
                return Err(anyhow!(
                    "setting recieve timeout failed with code {}",
                    WSAGetLastError().0
                ));
            }
            _ => {}
        }

        match setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, Some(TIMEOUT)) {
            SOCKET_ERROR => {
                return Err(anyhow!(
                    "setting send timeout failed with code {}",
                    WSAGetLastError().0
                ));
            }
            _ => {}
        }

        let mut sock_addr = SOCKADDR_IN::default();
        sock_addr.sin_addr = IN_ADDR::from(Ipv4Addr::from(destination));
        sock_addr.sin_family = AF_INET;

        let request = make_packet(data)?;

        match sendto(
            s,
            request.as_slice(),
            0,
            transmute::<&SOCKADDR_IN, *const SOCKADDR>(&sock_addr),
            size_of::<SOCKADDR_IN>() as i32,
        ) {
            r if r == request.len() as i32 => {}
            _ => match WSAGetLastError() {
                WSAETIMEDOUT => return Err(anyhow!("timed out")),
                WSAEMSGSIZE => return Err(anyhow!("packet too large")),
                e => return Err(anyhow!("recv failed with code {}", e.0)),
            },
        };

        let reply_size = match recv(s, REPLY_BUFFER.as_mut(), SEND_RECV_FLAGS(0)) {
            SOCKET_ERROR => match WSAGetLastError() {
                WSAETIMEDOUT => return Err(anyhow!("timed out")),
                WSAEMSGSIZE => return Err(anyhow!("packet too large")),
                e => return Err(anyhow!("recv failed with code {}", e.0)),
            },
            r => r,
        };

        let headers = match PacketHeaders::from_ip_slice(&REPLY_BUFFER[..reply_size as usize]) {
            Ok(ph) => ph,
            Err(e) => return Err(anyhow!("failed to parse packet: {}", e)),
        };

        let res = match headers.payload {
            PayloadSlice::Icmpv4(pl) => Ok(Vec::<u8>::from(pl)),
            PayloadSlice::Empty => Err(anyhow!("no payload found")),
            _ => Err(anyhow!("malformed payload found (not ICMPv4)")),
        };

        match closesocket(s) {
            SOCKET_ERROR => {
                return Err(anyhow!(
                    "closesocket failed with code {}",
                    WSAGetLastError().0
                ));
            }
            _ => res,
        }
    }
}
