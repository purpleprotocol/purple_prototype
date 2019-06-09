/*
  Copyright 2018 The Purple Library Authors
  This file is part of the Purple Library.

  The Purple Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Library. If not, see <http://www.gnu.org/licenses/>.
*/

use crate::error::NetworkErr;
use crypto::{Nonce, KxPublicKey};
use crypto::crc32fast::Hasher;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

pub const NETWORK_VERSION: u8 = 0;

/// Encrypts and wraps a packet with the default network header
/// 
/// ### Header fields
/// 1) Network layer version   - 8bits
/// 2) Packet length           - 32bits
/// 3) CRC32 of packet + nonce - 32bits
/// 4) Nonce                   - 12bytes
/// 5) Packet                  - Binary of packet length
pub fn wrap_packet(packet: &[u8], key: &KxPublicKey) -> Vec<u8> {
    let (encrypted, nonce) = crypto::seal(packet, key);
    let packet_len = encrypted.len();
    let mut buf: Vec<u8> = Vec::with_capacity(21 + packet_len);
    let mut crc32 = Hasher::new();

    crc32.update(&encrypted);
    crc32.update(&nonce.0);

    let crc32 = crc32.finalize();

    buf.write_u8(NETWORK_VERSION).unwrap();
    buf.write_u32::<BigEndian>(packet_len as u32).unwrap();
    buf.write_u32::<BigEndian>(crc32).unwrap();
    buf.extend_from_slice(&nonce.0);
    buf.extend_from_slice(&encrypted);
    buf
}


/// Attempts to decrypt a packet
pub fn unwrap_packet(packet: &[u8], key: &KxPublicKey) -> Result<Vec<u8>, NetworkErr> {
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

    let packet_len = if let Ok(result) = rdr.read_u32::<BigEndian>() {
        result
    } else {
        return Err(NetworkErr::BadFormat);
    };

    rdr.set_position(5);

    let packet_crc32 = if let Ok(result) = rdr.read_u32::<BigEndian>() {
        result
    } else {
        return Err(NetworkErr::BadFormat);
    };

    let mut buf: Vec<u8> = rdr.into_inner();
    let _: Vec<u8> = buf.drain(..9).collect();

    let nonce = if buf.len() > 12 as usize {
        let mut nonce = [0; 12];
        let nonce_vec: Vec<u8> = buf.drain(..12).collect();

        nonce.copy_from_slice(&nonce_vec);

        Nonce(nonce)
    } else {
        return Err(NetworkErr::BadFormat);
    };

    let packet = if buf.len() == packet_len as usize {
        buf
    } else {
        return Err(NetworkErr::BadFormat);
    };

    let mut crc32 = Hasher::new();

    crc32.update(&packet);
    crc32.update(&nonce.0);

    let crc32 = crc32.finalize();

    // Check CRC32 checksum
    if crc32 != packet_crc32 {
        return Err(NetworkErr::BadCRC32);
    }

    match crypto::open(&packet, key, &nonce) {
        Ok(result) => Ok(result),
        Err(_) => Err(NetworkErr::EncryptionErr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn wrap_unwrap(packet: Vec<u8>) -> bool {
            let key = KxPublicKey([0; 32]);

            assert_eq!(packet, unwrap_packet(&wrap_packet(&packet, &key), &key).unwrap());
            true
        }
    }
}