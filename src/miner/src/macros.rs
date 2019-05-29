/// Macro to clean up u64 unwrapping
#[macro_export]
macro_rules! to_u64 {
    ($n:expr) => {
        $n.to_u64().ok_or(ErrorKind::IntegerCast)?
    };
}

/// Macro to clean up u64 unwrapping as u32
#[macro_export]
macro_rules! to_u32 {
    ($n:expr) => {
        $n.to_u64().ok_or(ErrorKind::IntegerCast)? as u32
    };
}

/// Macro to clean up u64 unwrapping as usize
#[macro_export]
macro_rules! to_usize {
    ($n:expr) => {
        $n.to_u64().ok_or(ErrorKind::IntegerCast)? as usize
    };
}

/// Macro to clean up casting to edge type
/// TODO: this macro uses unhygenic data T
#[macro_export]
macro_rules! to_edge {
    ($n:expr) => {
        T::from($n).ok_or(ErrorKind::IntegerCast)?
    };
}

#[macro_export]
macro_rules! max {
    ($x: expr) => ($x);
    ($x: expr, $($z: expr),+) => {{
        let y = max!($($z),*);
        if $x > y {
            $x
        } else {
            y
        }
    }}
}