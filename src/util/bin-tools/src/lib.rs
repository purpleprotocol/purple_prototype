#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[macro_export]
macro_rules! encode_u8 {
    ($x:expr) => {{
        use byteorder::WriteBytesExt;

        let mut buf: Vec<u8> = Vec::with_capacity(1);
        buf.write_u8($x).unwrap();

        buf
    }}
}

#[macro_export]
macro_rules! decode_u8 {
    ($x:expr) => {{
        use byteorder::ReadBytesExt;
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u8()
    }}
}

#[macro_export]
macro_rules! encode_be_u16 {
    ($x:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(2);
        buf.write_u16::<BigEndian>($x).unwrap();

        buf
    }}
}

#[macro_export]
macro_rules! decode_be_u16 {
    ($x:expr) => {{
        use byteorder::{BigEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u16::<BigEndian>()
    }}
}

#[macro_export]
macro_rules! encode_be_u32 {
    ($x:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};
        
        let mut buf: Vec<u8> = Vec::with_capacity(4);
        buf.write_u32::<BigEndian>($x).unwrap();

        buf
    }}
}

#[macro_export]
macro_rules! decode_be_u32 {
    ($x:expr) => {{
        use byteorder::{BigEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u32::<BigEndian>()
    }}
}

#[macro_export]
macro_rules! encode_be_u64 {
    ($x:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(8);
        buf.write_u64::<BigEndian>($x).unwrap();

        buf
    }}
}

#[macro_export]
macro_rules! decode_be_u64 {
    ($x:expr) => {{
        use byteorder::{BigEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u64::<BigEndian>()
    }}
}

#[macro_export]
macro_rules! encode_le_u16 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(2);
        buf.write_u16::<LittleEndian>($x).unwrap();

        buf
    }}
}

#[macro_export]
macro_rules! decode_le_u16 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u16::<LittleEndian>()
    }}
}

#[macro_export]
macro_rules! encode_le_u32 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(4);
        buf.write_u32::<LittleEndian>($x).unwrap();

        buf
    }}
}

#[macro_export]
macro_rules! decode_le_u32 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u32::<LittleEndian>()
    }}
}

#[macro_export]
macro_rules! encode_le_u64 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(8);
        buf.write_u64::<LittleEndian>($x).unwrap();

        buf
    }}
}

#[macro_export]
macro_rules! decode_le_u64 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u64::<LittleEndian>()
    }}
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn u8(num: u8) -> bool {
            num == decode_u8!(encode_u8!(num)).unwrap()
        }

        fn be_u16(num: u16) -> bool {
            num == decode_be_u16!(encode_be_u16!(num)).unwrap()
        }

        fn be_u32(num: u32) -> bool {
            num == decode_be_u32!(encode_be_u32!(num)).unwrap()
        }

        fn be_u64(num: u64) -> bool {
            num == decode_be_u64!(encode_be_u64!(num)).unwrap()
        }

        fn le_u16(num: u16) -> bool {
            num == decode_le_u16!(encode_le_u16!(num)).unwrap()
        }

        fn le_u32(num: u32) -> bool {
            num == decode_le_u32!(encode_le_u32!(num)).unwrap()
        }

        fn le_u64(num: u64) -> bool {
            num == decode_le_u64!(encode_le_u64!(num)).unwrap()
        }
    }
}
