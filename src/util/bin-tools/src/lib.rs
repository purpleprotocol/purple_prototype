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
    }};
}

#[macro_export]
macro_rules! decode_u8 {
    ($x:expr) => {{
        use byteorder::ReadBytesExt;
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u8()
    }};
}

#[macro_export]
macro_rules! encode_be_u16 {
    ($x:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(2);
        buf.write_u16::<BigEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_be_u16 {
    ($x:expr) => {{
        use byteorder::{BigEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u16::<BigEndian>()
    }};
}

#[macro_export]
macro_rules! encode_be_u32 {
    ($x:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(4);
        buf.write_u32::<BigEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_be_u32 {
    ($x:expr) => {{
        use byteorder::{BigEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u32::<BigEndian>()
    }};
}

#[macro_export]
macro_rules! encode_be_u64 {
    ($x:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(8);
        buf.write_u64::<BigEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_be_u64 {
    ($x:expr) => {{
        use byteorder::{BigEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u64::<BigEndian>()
    }};
}

#[macro_export]
macro_rules! encode_le_u16 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(2);
        buf.write_u16::<LittleEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_le_u16 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u16::<LittleEndian>()
    }};
}

#[macro_export]
macro_rules! encode_le_u32 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(4);
        buf.write_u32::<LittleEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_le_u32 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u32::<LittleEndian>()
    }};
}

#[macro_export]
macro_rules! encode_le_u64 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(8);
        buf.write_u64::<LittleEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_le_u64 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_u64::<LittleEndian>()
    }};
}

#[macro_export]
macro_rules! encode_i8 {
    ($x:expr) => {{
        use byteorder::WriteBytesExt;

        let mut buf: Vec<u8> = Vec::with_capacity(1);
        buf.write_i8($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_i8 {
    ($x:expr) => {{
        use byteorder::ReadBytesExt;
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_i8()
    }};
}

#[macro_export]
macro_rules! encode_be_i16 {
    ($x:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(2);
        buf.write_i16::<BigEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_be_i16 {
    ($x:expr) => {{
        use byteorder::{BigEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_i16::<BigEndian>()
    }};
}

#[macro_export]
macro_rules! encode_be_i32 {
    ($x:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(4);
        buf.write_i32::<BigEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_be_i32 {
    ($x:expr) => {{
        use byteorder::{BigEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_i32::<BigEndian>()
    }};
}

#[macro_export]
macro_rules! encode_be_i64 {
    ($x:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(8);
        buf.write_i64::<BigEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_be_i64 {
    ($x:expr) => {{
        use byteorder::{BigEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_i64::<BigEndian>()
    }};
}

#[macro_export]
macro_rules! encode_le_i16 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(2);
        buf.write_i16::<LittleEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_le_i16 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_i16::<LittleEndian>()
    }};
}

#[macro_export]
macro_rules! encode_le_i32 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(4);
        buf.write_i32::<LittleEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_le_i32 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_i32::<LittleEndian>()
    }};
}

#[macro_export]
macro_rules! encode_le_i64 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(8);
        buf.write_i64::<LittleEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_le_i64 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_i64::<LittleEndian>()
    }};
}

#[macro_export]
macro_rules! encode_f8 {
    ($x:expr) => {{
        use byteorder::WriteBytesExt;

        let mut buf: Vec<u8> = Vec::with_capacity(1);
        buf.write_f8($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! encode_be_f32 {
    ($x:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(4);
        buf.write_f32::<BigEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_be_f32 {
    ($x:expr) => {{
        use byteorder::{BigEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_f32::<BigEndian>()
    }};
}

#[macro_export]
macro_rules! encode_be_f64 {
    ($x:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(8);
        buf.write_f64::<BigEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_be_f64 {
    ($x:expr) => {{
        use byteorder::{BigEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_f64::<BigEndian>()
    }};
}

#[macro_export]
macro_rules! encode_le_f32 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(4);
        buf.write_f32::<LittleEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_le_f32 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_f32::<LittleEndian>()
    }};
}

#[macro_export]
macro_rules! encode_le_f64 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut buf: Vec<u8> = Vec::with_capacity(8);
        buf.write_f64::<LittleEndian>($x).unwrap();

        buf
    }};
}

#[macro_export]
macro_rules! decode_le_f64 {
    ($x:expr) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let mut cursor = Cursor::new($x);
        cursor.read_f64::<LittleEndian>()
    }};
}

/// Returns a HashSet containing the passed values.
#[macro_export]
macro_rules! set {
    ($fst:expr $(, $v:expr)*) => ({
        let mut set = HashSet::with_capacity(count!($fst $(, $v)*));

        set.insert($fst);
        $(set.insert($v);)*

        set
    });
}

/// Counts the number of values passed to it.
#[macro_export]
macro_rules! count {
    () => (0);
    ($fst:expr) => (1);
    ($fst:expr, $snd:expr) => (2);
    ($fst:expr, $snd:expr $(, $v:expr)*) => (1 + count!($snd $(, $v)*));
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

        fn i8(num: i8) -> bool {
            num == decode_i8!(encode_i8!(num)).unwrap()
        }

        fn be_i16(num: i16) -> bool {
            num == decode_be_i16!(encode_be_i16!(num)).unwrap()
        }

        fn be_i32(num: i32) -> bool {
            num == decode_be_i32!(encode_be_i32!(num)).unwrap()
        }

        fn be_i64(num: i64) -> bool {
            num == decode_be_i64!(encode_be_i64!(num)).unwrap()
        }

        fn le_i16(num: i16) -> bool {
            num == decode_le_i16!(encode_le_i16!(num)).unwrap()
        }

        fn le_i32(num: i32) -> bool {
            num == decode_le_i32!(encode_le_i32!(num)).unwrap()
        }

        fn le_i64(num: i64) -> bool {
            num == decode_le_i64!(encode_le_i64!(num)).unwrap()
        }

        fn be_f32(num: f32) -> bool {
            num == decode_be_f32!(encode_be_f32!(num)).unwrap()
        }

        fn be_f64(num: f64) -> bool {
            num == decode_be_f64!(encode_be_f64!(num)).unwrap()
        }

        fn le_f32(num: f32) -> bool {
            num == decode_le_f32!(encode_le_f32!(num)).unwrap()
        }

        fn le_f64(num: f64) -> bool {
            num == decode_le_f64!(encode_le_f64!(num)).unwrap()
        }
    }
}
