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
