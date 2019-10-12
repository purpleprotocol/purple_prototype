/*
  Copyright (C) 2018-2019 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/

use crate::error::NetworkErr;
use crate::header::PacketHeader;
use crate::interface::NetworkInterface;
use crate::packet::Packet;
use crate::packets::*;
use crate::peer::ConnectionType;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::crc32fast::Hasher;
use crypto::{Nonce, SecretKey as Sk, SessionKey, Signature};
use std::io::Cursor;
use std::net::SocketAddr;

pub const NETWORK_VERSION: u8 = 0;
pub const HEADER_SIZE: usize = 7; // Total of 7 bytes. 1 + 2 + 4;

/// Encrypts and wraps a packet with the default network header. Also signs
/// the encrypted packet and attaches the signature to the packet.
pub fn wrap_encrypt_packet(
    packet: &[u8],
    node_sk: &Sk,
    key: &SessionKey,
    network_name: &str,
) -> Vec<u8> {
    let (encrypted, nonce) = crypto::seal(packet, key);
    let sig = crypto::sign(encrypted.as_slice(), node_sk);
    let sig_bytes = sig.inner_bytes();
    wrap_packet(
        &[&nonce.0, sig_bytes.as_slice(), encrypted.as_slice()].concat(),
        network_name,
    )
}

/// Wraps a packet without encrypting it.
///
/// ### Header fields
/// 1) Network layer version          - 8bits
/// 2) Packet length                  - 16bits
/// 3) CRC32 of packet + network name - 32bits
/// 4) Packet                         - Binary of packet length
pub fn wrap_packet(packet: &[u8], network_name: &str) -> Vec<u8> {
    let packet_len = packet.len();
    let mut buf: Vec<u8> = Vec::with_capacity(HEADER_SIZE + packet_len);
    let mut crc32 = Hasher::new();

    crc32.update(packet);
    crc32.update(network_name.as_bytes());
    let crc32 = crc32.finalize();

    buf.write_u8(NETWORK_VERSION).unwrap();
    buf.write_u16::<BigEndian>(packet_len as u16).unwrap();
    buf.write_u32::<BigEndian>(crc32).unwrap();
    buf.extend_from_slice(packet);
    buf
}

/// Attempts to decode a `PacketHeader` from a slice of bytes.
pub fn decode_header(header: &[u8]) -> Result<PacketHeader, NetworkErr> {
    if header.len() != HEADER_SIZE {
        return Err(NetworkErr::BadHeader);
    }

    let mut rdr = Cursor::new(header.to_vec());
    let network_version = if let Ok(result) = rdr.read_u8() {
        result
    } else {
        return Err(NetworkErr::BadFormat);
    };

    if network_version != NETWORK_VERSION {
        return Err(NetworkErr::BadVersion);
    }

    rdr.set_position(1);

    let packet_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
        result
    } else {
        return Err(NetworkErr::BadHeader);
    };

    if packet_len < 12 + 64 {
        return Err(NetworkErr::BadFormat);
    }

    rdr.set_position(3);

    let crc32 = if let Ok(result) = rdr.read_u32::<BigEndian>() {
        result
    } else {
        return Err(NetworkErr::BadHeader);
    };

    Ok(PacketHeader {
        packet_len,
        crc32,
        network_version,
    })
}

/// Verifies the CRC32 checksum of the packet returning `Err(NetworkErr::BadCRC32)` if invalid.
pub fn verify_crc32(
    header: &PacketHeader,
    packet: &[u8],
    network_name: &str,
) -> Result<(), NetworkErr> {
    let mut crc32 = Hasher::new();

    crc32.update(packet);
    crc32.update(network_name.as_bytes());
    let crc32 = crc32.finalize();

    // Check CRC32 checksum
    if crc32 != header.crc32 {
        return Err(NetworkErr::BadCRC32);
    }

    Ok(())
}

/// Attempts to decrypt a packet
pub fn decrypt(packet: &[u8], nonce: &Nonce, key: &SessionKey) -> Result<Vec<u8>, NetworkErr> {
    match crypto::open(packet, key, nonce) {
        Ok(result) => Ok(result),
        Err(_) => Err(NetworkErr::EncryptionErr),
    }
}

/// Parses and handles a packet.
pub fn handle_packet<N: NetworkInterface>(
    network: &mut N,
    conn_type: ConnectionType,
    peer_addr: &SocketAddr,
    packet: &[u8],
) -> Result<(), NetworkErr> {
    let packet_type = packet[0];

    match packet_type {
        Ping::PACKET_TYPE => match Ping::from_bytes(packet) {
            Ok(packet) => Ping::handle(network, peer_addr, &packet, conn_type)?,
            _ => return Err(NetworkErr::PacketParseErr),
        },

        Pong::PACKET_TYPE => match Pong::from_bytes(packet) {
            Ok(packet) => Pong::handle(network, peer_addr, &packet, conn_type)?,
            _ => return Err(NetworkErr::PacketParseErr),
        },

        RequestPeers::PACKET_TYPE => match RequestPeers::from_bytes(packet) {
            Ok(packet) => RequestPeers::handle(network, peer_addr, &packet, conn_type)?,
            _ => return Err(NetworkErr::PacketParseErr),
        },

        SendPeers::PACKET_TYPE => match SendPeers::from_bytes(packet) {
            Ok(packet) => SendPeers::handle(network, peer_addr, &packet, conn_type)?,
            _ => return Err(NetworkErr::PacketParseErr),
        },

        ForwardBlock::PACKET_TYPE => match ForwardBlock::from_bytes(packet) {
            Ok(packet) => ForwardBlock::handle(network, peer_addr, &packet, conn_type)?,
            _ => return Err(NetworkErr::PacketParseErr),
        },

        _ => {
            debug!("Could not parse packet with type {} from {}", packet_type, peer_addr);
            return Err(NetworkErr::PacketParseErr);
        }
    }

    Ok(())
}

#[cfg(test)]
/// Attempts to decrypt a packet. Only used for testing
pub fn unwrap_decrypt_packet(
    packet: &[u8],
    key: &SessionKey,
    network_name: &str,
) -> Result<Vec<u8>, NetworkErr> {
    let mut rdr = Cursor::new(packet.to_vec());
    let version = if let Ok(result) = rdr.read_u8() {
        result
    } else {
        return Err(NetworkErr::BadFormat);
    };

    if version != NETWORK_VERSION {
        return Err(NetworkErr::BadVersion);
    }

    rdr.set_position(1);

    let packet_len = if let Ok(result) = rdr.read_u16::<BigEndian>() {
        result
    } else {
        return Err(NetworkErr::BadFormat);
    };

    if packet_len < 12 + 64 {
        return Err(NetworkErr::BadFormat);
    }

    rdr.set_position(3);

    let packet_crc32 = if let Ok(result) = rdr.read_u32::<BigEndian>() {
        result
    } else {
        return Err(NetworkErr::BadFormat);
    };

    let mut buf: Vec<u8> = rdr.into_inner();
    let _: Vec<u8> = buf.drain(..7).collect();

    let nonce = if buf.len() > 12 as usize {
        let mut nonce = [0; 12];
        let nonce_vec: Vec<u8> = buf.drain(..12).collect();

        nonce.copy_from_slice(&nonce_vec);

        Nonce(nonce)
    } else {
        return Err(NetworkErr::BadFormat);
    };

    let sig = if buf.len() > 64 as usize {
        let sig_vec: Vec<u8> = buf.drain(..64).collect();
        Signature::new(&sig_vec)
    } else {
        return Err(NetworkErr::BadFormat);
    };

    let packet = if buf.len() == (packet_len - 12 - 64) as usize {
        buf
    } else {
        return Err(NetworkErr::BadFormat);
    };

    let mut crc32 = Hasher::new();

    crc32.update(&nonce.0);
    crc32.update(&sig.inner_bytes());
    crc32.update(&packet);
    crc32.update(network_name.as_bytes());

    let crc32 = crc32.finalize();

    // Check CRC32 checksum
    if crc32 != packet_crc32 {
        return Err(NetworkErr::BadCRC32);
    }

    decrypt(&packet, &nonce, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Identity;
    use rand::prelude::*;

    quickcheck! {
        fn wrap_encrypt_unwrap(packet: Vec<u8>) -> bool {
            let id = Identity::new();
            let key = SessionKey([0; 32]);

            assert_eq!(packet, unwrap_decrypt_packet(&wrap_encrypt_packet(&packet, id.skey(), &key, "test"), &key, "test").unwrap());
            true
        }

        fn decode_header() -> bool {
            let mut rng = rand::thread_rng();
            let packet: Vec<u8> = (0..128)
                .into_iter()
                .map(|_| rng.gen())
                .collect();
            let wrapped = wrap_packet(&packet, "test");
            let (header, _tail) = wrapped.split_at(7);
            super::decode_header(&header).unwrap();
            true
        }
    }
}
