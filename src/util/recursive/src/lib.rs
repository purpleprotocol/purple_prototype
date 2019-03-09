pub enum RecResult<C, R> {
    Continue(C),
    Return(R),
}

pub fn tail_recurse<C, R>(mut init: C, mut f: impl FnMut(C) -> RecResult<C, R>) -> R {
    loop {
        match f(init) {
            RecResult::Continue(c) => init = c,
            RecResult::Return(r) => return r,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = tail_recurse((5, 1), |(a, b)| {
            if a == 0 {
                RecResult::Return(b)
            } else {
                RecResult::Continue((a - 1, a * b))
            }
        });

        assert_eq!(result, 120);
    }
}
