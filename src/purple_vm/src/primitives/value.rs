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

use std::cmp::{Ordering, PartialOrd};
use std::fmt;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Rem, Shl, Shr, Sub};
use std::{f32, f64};
use VmError;

// TODO: When the const generics feature (https://github.com/rust-lang/rfcs/blob/master/text/2000-const-generics.md) 
// gets to a stable version remove the conversions done on arrays with length greather than 32

#[derive(Clone, Copy)]
pub enum VmValue {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    i32Array2([i32; 2]),
    i32Array4([i32; 4]),
    i32Array8([i32; 8]),
    i32Array16([i32; 16]),
    i32Array32([i32; 32]),
    i32Array64([i32; 64]),
    i32Array128([i32; 128]),
    i32Array256([i32; 256]),
    i64Array2([i64; 2]),
    i64Array4([i64; 4]),
    i64Array8([i64; 8]),
    i64Array16([i64; 16]),
    i64Array32([i64; 32]),
    i64Array64([i64; 64]),
    i64Array128([i64; 128]),
    i64Array256([i64; 256]),
    f32Array2([f32; 2]),
    f32Array4([f32; 4]),
    f32Array8([f32; 8]),
    f32Array16([f32; 16]),
    f32Array32([f32; 32]),
    f32Array64([f32; 64]),
    f32Array128([f32; 128]),
    f32Array256([f32; 256]),
    f64Array2([f64; 2]),
    f64Array4([f64; 4]),
    f64Array8([f64; 8]),
    f64Array16([f64; 16]),
    f64Array32([f64; 32]),
    f64Array64([f64; 64]),
    f64Array128([f64; 128]),
    f64Array256([f64; 256]),
}

impl VmValue {
    /// Returns the byte size of the inner value.
    pub fn byte_size(&self) -> usize {
        match *self {
            VmValue::I32(_) => 4,
            VmValue::I64(_) => 8,
            VmValue::F32(_) => 4,
            VmValue::F64(_) => 8,
            VmValue::i32Array2(_) => 8,
            VmValue::i32Array4(_) => 16,
            VmValue::i32Array8(_) => 32,
            VmValue::i32Array16(_) => 64,
            VmValue::i32Array32(_) => 128,
            VmValue::i32Array64(_) => 256,
            VmValue::i32Array128(_) => 512,
            VmValue::i32Array256(_) => 1024,
            VmValue::i64Array2(_) => 16,
            VmValue::i64Array4(_) => 32,
            VmValue::i64Array8(_) => 64,
            VmValue::i64Array16(_) => 128,
            VmValue::i64Array32(_) => 256,
            VmValue::i64Array64(_) => 512,
            VmValue::i64Array128(_) => 1024,
            VmValue::i64Array256(_) => 2048,
            VmValue::f32Array2(_) => 8,
            VmValue::f32Array4(_) => 16,
            VmValue::f32Array8(_) => 32,
            VmValue::f32Array16(_) => 64,
            VmValue::f32Array32(_) => 128,
            VmValue::f32Array64(_) => 256,
            VmValue::f32Array128(_) => 512,
            VmValue::f32Array256(_) => 1024,
            VmValue::f64Array2(_) => 16,
            VmValue::f64Array4(_) => 32,
            VmValue::f64Array8(_) => 64,
            VmValue::f64Array16(_) => 128,
            VmValue::f64Array32(_) => 256,
            VmValue::f64Array64(_) => 512,
            VmValue::f64Array128(_) => 1024,
            VmValue::f64Array256(_) => 2048,
        }
    }

    pub fn is_positive(&self) -> bool {
        match *self {
            VmValue::I32(val) => val >= 0,
            VmValue::I64(val) => val >= 0,
            VmValue::F32(val) => val >= 0.0,
            VmValue::F64(val) => val >= 0.0,
            VmValue::i32Array2(val) => val.iter().all(|&v| v >= 0),
            VmValue::i32Array4(val) => val.iter().all(|&v| v >= 0),
            VmValue::i32Array8(val) => val.iter().all(|&v| v >= 0),
            VmValue::i32Array16(val) => val.iter().all(|&v| v >= 0),
            VmValue::i32Array32(val) => val.iter().all(|&v| v >= 0),
            VmValue::i32Array64(val) => val.iter().all(|&v| v >= 0),
            VmValue::i32Array128(val) => val.iter().all(|&v| v >= 0),
            VmValue::i32Array256(val) => val.iter().all(|&v| v >= 0),
            VmValue::i64Array2(val) => val.iter().all(|&v| v >= 0),
            VmValue::i64Array4(val) => val.iter().all(|&v| v >= 0),
            VmValue::i64Array8(val) => val.iter().all(|&v| v >= 0),
            VmValue::i64Array16(val) => val.iter().all(|&v| v >= 0),
            VmValue::i64Array32(val) => val.iter().all(|&v| v >= 0),
            VmValue::i64Array64(val) => val.iter().all(|&v| v >= 0),
            VmValue::i64Array128(val) => val.iter().all(|&v| v >= 0),
            VmValue::i64Array256(val) => val.iter().all(|&v| v >= 0),
            VmValue::f32Array2(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f32Array4(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f32Array8(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f32Array16(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f32Array32(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f32Array64(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f32Array128(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f32Array256(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f64Array2(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f64Array4(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f64Array8(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f64Array16(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f64Array32(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f64Array64(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f64Array128(val) => val.iter().all(|&v| v >= 0.0),
            VmValue::f64Array256(val) => val.iter().all(|&v| v >= 0.0),
        }
    }

    fn check_f32_infinite(val: f32) -> Option<f32> {
        if val.is_infinite() {
            None
        } else {
            Some(val)
        }
    }

    fn check_f64_infinite(val: f64) -> Option<f64> {
        if val.is_infinite() {
            None
        } else {
            Some(val)
        }
    }

    fn sum_f32(val1: &f32, val2: &f32) -> Option<f32> {
        VmValue::check_f32_infinite(val1 + val2)
    }

    fn sum_f64(val1: &f64, val2: &f64) -> Option<f64> {
        VmValue::check_f64_infinite(val1 + val2)
    }

    fn sub_f32(val1: &f32, val2: &f32) -> Option<f32> {
        VmValue::check_f32_infinite(val1 - val2)
    }

    fn sub_f64(val1: &f64, val2: &f64) -> Option<f64> {
        VmValue::check_f64_infinite(val1 - val2)
    }

    fn mul_f32(val1: &f32, val2: &f32) -> Option<f32> {
        VmValue::check_f32_infinite(val1 * val2)
    }

    fn mul_f64(val1: &f64, val2: &f64) -> Option<f64> {
        VmValue::check_f64_infinite(val1 * val2)
    }

    fn div_f32(val1: &f32, val2: &f32) -> Result<f32, VmError> {
        if *val2 == 0.0 {
            return Err(VmError::DivideByZero);
        }

        match VmValue::check_f32_infinite(val1 / val2) {
            Some(res) => Ok(res),
            None => Err(VmError::Infinity),
        }
    }

    fn div_f64(val1: &f64, val2: &f64) -> Result<f64, VmError> {
        if *val2 == 0.0 {
            return Err(VmError::DivideByZero);
        }

        match VmValue::check_f64_infinite(val1 / val2) {
            Some(res) => Ok(res),
            None => Err(VmError::Infinity),
        }
    }

    fn rem_f32(val1: &f32, val2: &f32) -> Result<f32, VmError> {
        if *val2 == 0.0 {
            return Err(VmError::DivideByZero);
        }

        match VmValue::check_f32_infinite(val1 % val2) {
            Some(res) => Ok(res),
            None => Err(VmError::Infinity),
        }
    }

    fn rem_f64(val1: &f64, val2: &f64) -> Result<f64, VmError> {
        if *val2 == 0.0 {
            return Err(VmError::DivideByZero);
        }

        match VmValue::check_f64_infinite(val1 % val2) {
            Some(res) => Ok(res),
            None => Err(VmError::Infinity),
        }
    }

    pub fn abs(&self) -> Result<VmValue, VmError> {
        match *self {
            VmValue::I32(_) | VmValue::I64(_) => Err(VmError::InvalidOperator),
            VmValue::F32(val) => Ok(VmValue::F32(val.abs())),
            VmValue::F64(val) => Ok(VmValue::F64(val.abs())),
            VmValue::i32Array2(_)
            | VmValue::i32Array4(_)
            | VmValue::i32Array8(_)
            | VmValue::i32Array16(_)
            | VmValue::i32Array32(_)
            | VmValue::i32Array64(_)
            | VmValue::i32Array128(_)
            | VmValue::i32Array256(_)
            | VmValue::i64Array2(_)
            | VmValue::i64Array4(_)
            | VmValue::i64Array8(_)
            | VmValue::i64Array16(_)
            | VmValue::i64Array32(_)
            | VmValue::i64Array64(_)
            | VmValue::i64Array128(_)
            | VmValue::i64Array256(_) => Err(VmError::InvalidOperator),
            VmValue::f32Array2(val) => {
                let mut result: [f32; 2] = [0.0; 2];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f32Array2(result))
            }
            VmValue::f32Array4(val) => {
                let mut result: [f32; 4] = [0.0; 4];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f32Array4(result))
            }
            VmValue::f32Array8(val) => {
                let mut result: [f32; 8] = [0.0; 8];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f32Array8(result))
            }
            VmValue::f32Array16(val) => {
                let mut result: [f32; 16] = [0.0; 16];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f32Array16(result))
            }
            VmValue::f32Array32(val) => {
                let mut result: [f32; 32] = [0.0; 32];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f32Array32(result))
            }
            VmValue::f32Array64(val) => {
                let mut result: [f32; 64] = [0.0; 64];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f32Array64(result))
            }
            VmValue::f32Array128(val) => {
                let mut result: [f32; 128] = [0.0; 128];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f32Array128(result))
            }
            VmValue::f32Array256(val) => {
                let mut result: [f32; 256] = [0.0; 256];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f32Array256(result))
            }
            VmValue::f64Array2(val) => {
                let mut result: [f64; 2] = [0.0; 2];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f64Array2(result))
            }
            VmValue::f64Array4(val) => {
                let mut result: [f64; 4] = [0.0; 4];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f64Array4(result))
            }
            VmValue::f64Array8(val) => {
                let mut result: [f64; 8] = [0.0; 8];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f64Array8(result))
            }
            VmValue::f64Array16(val) => {
                let mut result: [f64; 16] = [0.0; 16];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f64Array16(result))
            }
            VmValue::f64Array32(val) => {
                let mut result: [f64; 32] = [0.0; 32];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f64Array32(result))
            }
            VmValue::f64Array64(val) => {
                let mut result: [f64; 64] = [0.0; 64];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f64Array64(result))
            }
            VmValue::f64Array128(val) => {
                let mut result: [f64; 128] = [0.0; 128];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f64Array128(result))
            }
            VmValue::f64Array256(val) => {
                let mut result: [f64; 256] = [0.0; 256];
                let abs = val.iter().map(|a| a.abs());
                for (r, v) in result.iter_mut().zip(abs) {
                    *r = v;
                }

                Ok(VmValue::f64Array256(result))
            }
        }
    }

    pub fn ceil(&self) -> Result<VmValue, VmError> {
        match *self {
            VmValue::I32(_) => Err(VmError::InvalidOperator),
            VmValue::I64(_) => Err(VmError::InvalidOperator),
            VmValue::F32(val) => Ok(VmValue::F32(val.ceil())),
            VmValue::F64(val) => Ok(VmValue::F64(val.ceil())),
            VmValue::i32Array2(_)
            | VmValue::i32Array4(_)
            | VmValue::i32Array8(_)
            | VmValue::i32Array16(_)
            | VmValue::i32Array32(_)
            | VmValue::i32Array64(_)
            | VmValue::i32Array128(_)
            | VmValue::i32Array256(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array2(_)
            | VmValue::i64Array4(_)
            | VmValue::i64Array8(_)
            | VmValue::i64Array16(_)
            | VmValue::i64Array32(_)
            | VmValue::i64Array64(_)
            | VmValue::i64Array128(_)
            | VmValue::i64Array256(_) => Err(VmError::InvalidOperator),
            VmValue::f32Array2(val) => {
                let mut result: [f32; 2] = [0.0; 2];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f32Array2(result))
            }
            VmValue::f32Array4(val) => {
                let mut result: [f32; 4] = [0.0; 4];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f32Array4(result))
            }
            VmValue::f32Array8(val) => {
                let mut result: [f32; 8] = [0.0; 8];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f32Array8(result))
            }
            VmValue::f32Array16(val) => {
                let mut result: [f32; 16] = [0.0; 16];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f32Array16(result))
            }
            VmValue::f32Array32(val) => {
                let mut result: [f32; 32] = [0.0; 32];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f32Array32(result))
            }
            VmValue::f32Array64(val) => {
                let mut result: [f32; 64] = [0.0; 64];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f32Array64(result))
            }
            VmValue::f32Array128(val) => {
                let mut result: [f32; 128] = [0.0; 128];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f32Array128(result))
            }
            VmValue::f32Array256(val) => {
                let mut result: [f32; 256] = [0.0; 256];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f32Array256(result))
            }
            VmValue::f64Array2(val) => {
                let mut result: [f64; 2] = [0.0; 2];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f64Array2(result))
            }
            VmValue::f64Array4(val) => {
                let mut result: [f64; 4] = [0.0; 4];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f64Array4(result))
            }
            VmValue::f64Array8(val) => {
                let mut result: [f64; 8] = [0.0; 8];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f64Array8(result))
            }
            VmValue::f64Array16(val) => {
                let mut result: [f64; 16] = [0.0; 16];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f64Array16(result))
            }
            VmValue::f64Array32(val) => {
                let mut result: [f64; 32] = [0.0; 32];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f64Array32(result))
            }
            VmValue::f64Array64(val) => {
                let mut result: [f64; 64] = [0.0; 64];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f64Array64(result))
            }
            VmValue::f64Array128(val) => {
                let mut result: [f64; 128] = [0.0; 128];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f64Array128(result))
            }
            VmValue::f64Array256(val) => {
                let mut result: [f64; 256] = [0.0; 256];
                let ceils = val.iter().map(|a| a.ceil());
                for (r, v) in result.iter_mut().zip(ceils) {
                    *r = v;
                }

                Ok(VmValue::f64Array256(result))
            }
        }
    }

    pub fn floor(&self) -> Result<VmValue, VmError> {
        match *self {
            VmValue::I32(_) => Err(VmError::InvalidOperator),
            VmValue::I64(_) => Err(VmError::InvalidOperator),
            VmValue::F32(val) => Ok(VmValue::F32(val.floor())),
            VmValue::F64(val) => Ok(VmValue::F64(val.floor())),
            VmValue::i32Array2(_)
            | VmValue::i32Array4(_)
            | VmValue::i32Array8(_)
            | VmValue::i32Array16(_)
            | VmValue::i32Array32(_)
            | VmValue::i32Array64(_)
            | VmValue::i32Array128(_)
            | VmValue::i32Array256(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array2(_)
            | VmValue::i64Array4(_)
            | VmValue::i64Array8(_)
            | VmValue::i64Array16(_)
            | VmValue::i64Array32(_)
            | VmValue::i64Array64(_)
            | VmValue::i64Array128(_)
            | VmValue::i64Array256(_) => Err(VmError::InvalidOperator),
            VmValue::f32Array2(val) => {
                let mut result: [f32; 2] = [0.0; 2];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f32Array2(result))
            }
            VmValue::f32Array4(val) => {
                let mut result: [f32; 4] = [0.0; 4];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f32Array4(result))
            }
            VmValue::f32Array8(val) => {
                let mut result: [f32; 8] = [0.0; 8];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f32Array8(result))
            }
            VmValue::f32Array16(val) => {
                let mut result: [f32; 16] = [0.0; 16];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f32Array16(result))
            }
            VmValue::f32Array32(val) => {
                let mut result: [f32; 32] = [0.0; 32];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f32Array32(result))
            }
            VmValue::f32Array64(val) => {
                let mut result: [f32; 64] = [0.0; 64];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f32Array64(result))
            }
            VmValue::f32Array128(val) => {
                let mut result: [f32; 128] = [0.0; 128];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f32Array128(result))
            }
            VmValue::f32Array256(val) => {
                let mut result: [f32; 256] = [0.0; 256];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f32Array256(result))
            }
            VmValue::f64Array2(val) => {
                let mut result: [f64; 2] = [0.0; 2];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f64Array2(result))
            }
            VmValue::f64Array4(val) => {
                let mut result: [f64; 4] = [0.0; 4];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f64Array4(result))
            }
            VmValue::f64Array8(val) => {
                let mut result: [f64; 8] = [0.0; 8];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f64Array8(result))
            }
            VmValue::f64Array16(val) => {
                let mut result: [f64; 16] = [0.0; 16];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f64Array16(result))
            }
            VmValue::f64Array32(val) => {
                let mut result: [f64; 32] = [0.0; 32];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f64Array32(result))
            }
            VmValue::f64Array64(val) => {
                let mut result: [f64; 64] = [0.0; 64];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f64Array64(result))
            }
            VmValue::f64Array128(val) => {
                let mut result: [f64; 128] = [0.0; 128];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f64Array128(result))
            }
            VmValue::f64Array256(val) => {
                let mut result: [f64; 256] = [0.0; 256];
                let floors = val.iter().map(|a| a.floor());
                for (r, v) in result.iter_mut().zip(floors) {
                    *r = v;
                }

                Ok(VmValue::f64Array256(result))
            }
        }
    }

    pub fn trunc(&self) -> Result<VmValue, VmError> {
        match *self {
            VmValue::I32(_) => Err(VmError::InvalidOperator),
            VmValue::I64(_) => Err(VmError::InvalidOperator),
            VmValue::F32(val) => Ok(VmValue::F32(val.trunc())),
            VmValue::F64(val) => Ok(VmValue::F64(val.trunc())),
            VmValue::i32Array2(_)
            | VmValue::i32Array4(_)
            | VmValue::i32Array8(_)
            | VmValue::i32Array16(_)
            | VmValue::i32Array32(_)
            | VmValue::i32Array64(_)
            | VmValue::i32Array128(_)
            | VmValue::i32Array256(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array2(_)
            | VmValue::i64Array4(_)
            | VmValue::i64Array8(_)
            | VmValue::i64Array16(_)
            | VmValue::i64Array32(_)
            | VmValue::i64Array64(_)
            | VmValue::i64Array128(_)
            | VmValue::i64Array256(_) => Err(VmError::InvalidOperator),
            VmValue::f32Array2(val) => {
                let mut result: [f32; 2] = [0.0; 2];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f32Array2(result))
            }
            VmValue::f32Array4(val) => {
                let mut result: [f32; 4] = [0.0; 4];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f32Array4(result))
            }
            VmValue::f32Array8(val) => {
                let mut result: [f32; 8] = [0.0; 8];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f32Array8(result))
            }
            VmValue::f32Array16(val) => {
                let mut result: [f32; 16] = [0.0; 16];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f32Array16(result))
            }
            VmValue::f32Array32(val) => {
                let mut result: [f32; 32] = [0.0; 32];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f32Array32(result))
            }
            VmValue::f32Array64(val) => {
                let mut result: [f32; 64] = [0.0; 64];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f32Array64(result))
            }
            VmValue::f32Array128(val) => {
                let mut result: [f32; 128] = [0.0; 128];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f32Array128(result))
            }
            VmValue::f32Array256(val) => {
                let mut result: [f32; 256] = [0.0; 256];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f32Array256(result))
            }
            VmValue::f64Array2(val) => {
                let mut result: [f64; 2] = [0.0; 2];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f64Array2(result))
            }
            VmValue::f64Array4(val) => {
                let mut result: [f64; 4] = [0.0; 4];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f64Array4(result))
            }
            VmValue::f64Array8(val) => {
                let mut result: [f64; 8] = [0.0; 8];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f64Array8(result))
            }
            VmValue::f64Array16(val) => {
                let mut result: [f64; 16] = [0.0; 16];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f64Array16(result))
            }
            VmValue::f64Array32(val) => {
                let mut result: [f64; 32] = [0.0; 32];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f64Array32(result))
            }
            VmValue::f64Array64(val) => {
                let mut result: [f64; 64] = [0.0; 64];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f64Array64(result))
            }
            VmValue::f64Array128(val) => {
                let mut result: [f64; 128] = [0.0; 128];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f64Array128(result))
            }
            VmValue::f64Array256(val) => {
                let mut result: [f64; 256] = [0.0; 256];
                let truncs = val.iter().map(|a| a.trunc());
                for (r, v) in result.iter_mut().zip(truncs) {
                    *r = v;
                }

                Ok(VmValue::f64Array256(result))
            }
        }
    }

    pub fn round(&self) -> Result<VmValue, VmError> {
        match *self {
            VmValue::I32(_) => Err(VmError::InvalidOperator),
            VmValue::I64(_) => Err(VmError::InvalidOperator),
            VmValue::F32(val) => Ok(VmValue::F32(val.round())),
            VmValue::F64(val) => Ok(VmValue::F64(val.round())),
            VmValue::i32Array2(_)
            | VmValue::i32Array4(_)
            | VmValue::i32Array8(_)
            | VmValue::i32Array16(_)
            | VmValue::i32Array32(_)
            | VmValue::i32Array64(_)
            | VmValue::i32Array128(_)
            | VmValue::i32Array256(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array2(_)
            | VmValue::i64Array4(_)
            | VmValue::i64Array8(_)
            | VmValue::i64Array16(_)
            | VmValue::i64Array32(_)
            | VmValue::i64Array64(_)
            | VmValue::i64Array128(_)
            | VmValue::i64Array256(_) => Err(VmError::InvalidOperator),
            VmValue::f32Array2(val) => {
                let mut result: [f32; 2] = [0.0; 2];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f32Array2(result))
            }
            VmValue::f32Array4(val) => {
                let mut result: [f32; 4] = [0.0; 4];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f32Array4(result))
            }
            VmValue::f32Array8(val) => {
                let mut result: [f32; 8] = [0.0; 8];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f32Array8(result))
            }
            VmValue::f32Array16(val) => {
                let mut result: [f32; 16] = [0.0; 16];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f32Array16(result))
            }
            VmValue::f32Array32(val) => {
                let mut result: [f32; 32] = [0.0; 32];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f32Array32(result))
            }
            VmValue::f32Array64(val) => {
                let mut result: [f32; 64] = [0.0; 64];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f32Array64(result))
            }
            VmValue::f32Array128(val) => {
                let mut result: [f32; 128] = [0.0; 128];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f32Array128(result))
            }
            VmValue::f32Array256(val) => {
                let mut result: [f32; 256] = [0.0; 256];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f32Array256(result))
            }
            VmValue::f64Array2(val) => {
                let mut result: [f64; 2] = [0.0; 2];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f64Array2(result))
            }
            VmValue::f64Array4(val) => {
                let mut result: [f64; 4] = [0.0; 4];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f64Array4(result))
            }
            VmValue::f64Array8(val) => {
                let mut result: [f64; 8] = [0.0; 8];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f64Array8(result))
            }
            VmValue::f64Array16(val) => {
                let mut result: [f64; 16] = [0.0; 16];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f64Array16(result))
            }
            VmValue::f64Array32(val) => {
                let mut result: [f64; 32] = [0.0; 32];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f64Array32(result))
            }
            VmValue::f64Array64(val) => {
                let mut result: [f64; 64] = [0.0; 64];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f64Array64(result))
            }
            VmValue::f64Array128(val) => {
                let mut result: [f64; 128] = [0.0; 128];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f64Array128(result))
            }
            VmValue::f64Array256(val) => {
                let mut result: [f64; 256] = [0.0; 256];
                let rounded = val.iter().map(|a| a.round());
                for (r, v) in result.iter_mut().zip(rounded) {
                    *r = v;
                }

                Ok(VmValue::f64Array256(result))
            }
        }
    }

    pub fn copysign(&self, to_copy: &VmValue) -> Result<VmValue, VmError> {
        match (*self, *to_copy) {
            (VmValue::I32(_), VmValue::I32(_)) => Err(VmError::InvalidOperator),
            (VmValue::I64(_), VmValue::I64(_)) => Err(VmError::InvalidOperator),
            (VmValue::F32(val1), VmValue::F32(val2)) => Ok(VmValue::F32(val1.copysign(val2))),
            (VmValue::F64(val1), VmValue::F64(val2)) => Ok(VmValue::F64(val1.copysign(val2))),
            (VmValue::i32Array2(_), VmValue::i32Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array4(_), VmValue::i32Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array8(_), VmValue::i32Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array16(_), VmValue::i32Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array32(_), VmValue::i32Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array64(_), VmValue::i32Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array128(_), VmValue::i32Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array256(_), VmValue::i32Array256(_)) => Err(VmError::InvalidOperator),
            (VmValue::i64Array2(_), VmValue::i64Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::i64Array4(_), VmValue::i64Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::i64Array8(_), VmValue::i64Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::i64Array16(_), VmValue::i64Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::i64Array32(_), VmValue::i64Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::i64Array64(_), VmValue::i64Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::i64Array128(_), VmValue::i64Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::i64Array256(_), VmValue::i64Array256(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array2(val1), VmValue::f32Array2(val2)) => {
                let mut result: [f32; 2] = [0.0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f32Array2(result))
            }
            (VmValue::f32Array4(val1), VmValue::f32Array4(val2)) => {
                let mut result: [f32; 4] = [0.0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f32Array4(result))
            }
            (VmValue::f32Array8(val1), VmValue::f32Array8(val2)) => {
                let mut result: [f32; 8] = [0.0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f32Array8(result))
            }
            (VmValue::f32Array16(val1), VmValue::f32Array16(val2)) => {
                let mut result: [f32; 16] = [0.0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f32Array16(result))
            }
            (VmValue::f32Array32(val1), VmValue::f32Array32(val2)) => {
                let mut result: [f32; 32] = [0.0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f32Array32(result))
            }
            (VmValue::f32Array64(val1), VmValue::f32Array64(val2)) => {
                let mut result: [f32; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f32Array64(result))
            }
            (VmValue::f32Array128(val1), VmValue::f32Array128(val2)) => {
                let mut result: [f32; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f32Array128(result))
            }
            (VmValue::f32Array256(val1), VmValue::f32Array256(val2)) => {
                let mut result: [f32; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f32Array256(result))
            }
            (VmValue::f64Array2(val1), VmValue::f64Array2(val2)) => {
                let mut result: [f64; 2] = [0.0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f64Array2(result))
            }
            (VmValue::f64Array4(val1), VmValue::f64Array4(val2)) => {
                let mut result: [f64; 4] = [0.0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f64Array4(result))
            }
            (VmValue::f64Array8(val1), VmValue::f64Array8(val2)) => {
                let mut result: [f64; 8] = [0.0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f64Array8(result))
            }
            (VmValue::f64Array16(val1), VmValue::f64Array8(val2)) => {
                let mut result: [f64; 16] = [0.0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f64Array16(result))
            }
            (VmValue::f64Array32(val1), VmValue::f64Array32(val2)) => {
                let mut result: [f64; 32] = [0.0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f64Array32(result))
            }
            (VmValue::f64Array64(val1), VmValue::f64Array64(val2)) => {
                let mut result: [f64; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f64Array64(result))
            }
            (VmValue::f64Array128(val1), VmValue::f64Array128(val2)) => {
                let mut result: [f64; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f64Array128(result))
            }
            (VmValue::f64Array256(val1), VmValue::f64Array256(val2)) => {
                let mut result: [f64; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.copysign(*b));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::f64Array256(result))
            }
            (_, _) => panic!("Cannot perform copysign between different variants!"),
        }
    }

    pub fn rotate_left(&self, n: &VmValue) -> Result<VmValue, VmError> {
        match (*self, *n) {
            (VmValue::I32(val1), VmValue::I32(val2)) => {
                Ok(VmValue::I32(val1.rotate_left(val2 as u32)))
            }
            (VmValue::I64(val1), VmValue::I64(val2)) => {
                Ok(VmValue::I64(val1.rotate_left(val2 as u32)))
            }
            (VmValue::F32(_), VmValue::F32(_)) => Err(VmError::InvalidOperator),
            (VmValue::F64(_), VmValue::F64(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_left(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(_), VmValue::f32Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array4(_), VmValue::f32Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array8(_), VmValue::f32Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array16(_), VmValue::f32Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array32(_), VmValue::f32Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array64(_), VmValue::f32Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array128(_), VmValue::f32Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array256(_), VmValue::f32Array256(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array2(_), VmValue::f64Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array4(_), VmValue::f64Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array8(_), VmValue::f64Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array16(_), VmValue::f64Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array32(_), VmValue::f64Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array64(_), VmValue::f64Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array128(_), VmValue::f64Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array256(_), VmValue::f64Array256(_)) => Err(VmError::InvalidOperator),
            (_, _) => panic!("Cannot perform rotate_left between different variants!"),
        }
    }

    pub fn rotate_right(&self, n: &VmValue) -> Result<VmValue, VmError> {
        match (*self, *n) {
            (VmValue::I32(val1), VmValue::I32(val2)) => {
                Ok(VmValue::I32(val1.rotate_right(val2 as u32)))
            }
            (VmValue::I64(val1), VmValue::I64(val2)) => {
                Ok(VmValue::I64(val1.rotate_right(val2 as u32)))
            }
            (VmValue::F32(_), VmValue::F32(_)) => Err(VmError::InvalidOperator),
            (VmValue::F64(_), VmValue::F64(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a.rotate_right(*b as u32));
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(_), VmValue::f32Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array4(_), VmValue::f32Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array8(_), VmValue::f32Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array16(_), VmValue::f32Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array32(_), VmValue::f32Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array64(_), VmValue::f32Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array128(_), VmValue::f32Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array256(_), VmValue::f32Array256(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array2(_), VmValue::f64Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array4(_), VmValue::f64Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array8(_), VmValue::f64Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array16(_), VmValue::f64Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array32(_), VmValue::f64Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array64(_), VmValue::f64Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array128(_), VmValue::f64Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array256(_), VmValue::f64Array256(_)) => Err(VmError::InvalidOperator),
            (_, _) => panic!("Cannot perform rotate_right between different variants!"),
        }
    }

    pub fn sqrt(&self) -> Result<VmValue, VmError> {
        match *self {
            VmValue::I32(_) => Err(VmError::InvalidOperator),
            VmValue::I64(_) => Err(VmError::InvalidOperator),
            VmValue::F32(val) => {
                if !self.is_positive() {
                    return Err(VmError::DivideByZero);
                }
                Ok(VmValue::F32(val.sqrt()))
            }
            VmValue::F64(val) => {
                if !self.is_positive() {
                    return Err(VmError::DivideByZero);
                }
                Ok(VmValue::F64(val.sqrt()))
            }
            VmValue::i32Array2(_) => Err(VmError::InvalidOperator),
            VmValue::i32Array4(_) => Err(VmError::InvalidOperator),
            VmValue::i32Array8(_) => Err(VmError::InvalidOperator),
            VmValue::i32Array16(_) => Err(VmError::InvalidOperator),
            VmValue::i32Array32(_) => Err(VmError::InvalidOperator),
            VmValue::i32Array64(_) => Err(VmError::InvalidOperator),
            VmValue::i32Array128(_) => Err(VmError::InvalidOperator),
            VmValue::i32Array256(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array2(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array4(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array8(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array16(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array32(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array64(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array128(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array256(_) => Err(VmError::InvalidOperator),
            VmValue::f32Array2(val) => {
                let mut result: [f32; 2] = [0.0; 2];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array2(result))
            }
            VmValue::f32Array4(val) => {
                let mut result: [f32; 4] = [0.0; 4];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array4(result))
            }
            VmValue::f32Array8(val) => {
                let mut result: [f32; 8] = [0.0; 8];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array8(result))
            }
            VmValue::f32Array16(val) => {
                let mut result: [f32; 16] = [0.0; 16];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array16(result))
            }
            VmValue::f32Array32(val) => {
                let mut result: [f32; 32] = [0.0; 32];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array32(result))
            }
            VmValue::f32Array64(val) => {
                let mut result: [f32; 64] = [0.0; 64];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array64(result))
            }
            VmValue::f32Array128(val) => {
                let mut result: [f32; 128] = [0.0; 128];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array128(result))
            }
            VmValue::f32Array256(val) => {
                let mut result: [f32; 256] = [0.0; 256];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array256(result))
            }
            VmValue::f64Array2(val) => {
                let mut result: [f64; 2] = [0.0; 2];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array2(result))
            }
            VmValue::f64Array4(val) => {
                let mut result: [f64; 4] = [0.0; 4];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array4(result))
            }
            VmValue::f64Array8(val) => {
                let mut result: [f64; 8] = [0.0; 8];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array8(result))
            }
            VmValue::f64Array16(val) => {
                let mut result: [f64; 16] = [0.0; 16];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array16(result))
            }
            VmValue::f64Array32(val) => {
                let mut result: [f64; 32] = [0.0; 32];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array32(result))
            }
            VmValue::f64Array64(val) => {
                let mut result: [f64; 64] = [0.0; 64];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array64(result))
            }
            VmValue::f64Array128(val) => {
                let mut result: [f64; 128] = [0.0; 128];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array128(result))
            }
            VmValue::f64Array256(val) => {
                let mut result: [f64; 256] = [0.0; 256];
                let src = val.iter().map(|a| {
                    if *a < 0.0 {
                        Err(VmError::InvalidOperand)
                    } else {
                        Ok(a.sqrt())
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array256(result))
            }
        }
    }
}

impl PartialEq for VmValue {
    fn eq(&self, other: &VmValue) -> bool {
        match (*self, *other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => val1 == val2,
            (VmValue::I64(val1), VmValue::I64(val2)) => val1 == val2,
            (VmValue::F32(val1), VmValue::F32(val2)) => val1 == val2,
            (VmValue::F64(val1), VmValue::F64(val2)) => val1 == val2,
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => val1 == val2,
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => val1 == val2,
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => val1 == val2,
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => val1 == val2,
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => val1 == val2,
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => val1 == val2,
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => val1 == val2,
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => val1 == val2,
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => val1 == val2,
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => val1 == val2,
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (VmValue::f32Array2(val1), VmValue::f32Array2(val2)) => val1 == val2,
            (VmValue::f32Array4(val1), VmValue::f32Array4(val2)) => val1 == val2,
            (VmValue::f32Array8(val1), VmValue::f32Array8(val2)) => val1 == val2,
            (VmValue::f32Array16(val1), VmValue::f32Array16(val2)) => val1 == val2,
            (VmValue::f32Array32(val1), VmValue::f32Array32(val2)) => val1 == val2,
            (VmValue::f32Array64(val1), VmValue::f32Array64(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (VmValue::f32Array128(val1), VmValue::f32Array128(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (VmValue::f32Array256(val1), VmValue::f32Array256(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (VmValue::f64Array2(val1), VmValue::f64Array2(val2)) => val1 == val2,
            (VmValue::f64Array4(val1), VmValue::f64Array4(val2)) => val1 == val2,
            (VmValue::f64Array8(val1), VmValue::f64Array8(val2)) => val1 == val2,
            (VmValue::f64Array16(val1), VmValue::f64Array16(val2)) => val1 == val2,
            (VmValue::f64Array32(val1), VmValue::f64Array32(val2)) => val1 == val2,
            (VmValue::f64Array64(val1), VmValue::f64Array64(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (VmValue::f64Array128(val1), VmValue::f64Array128(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (VmValue::f64Array256(val1), VmValue::f64Array256(val2)) => {
                val1.to_vec() == val2.to_vec()
            }
            (_, _) => panic!("Cannot perform equality between different variants!"),
        }
    }
}

impl PartialOrd for VmValue {
    fn partial_cmp(&self, other: &VmValue) -> Option<Ordering> {
        match (self, other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => {
                if val1 < val2 {
                    Some(Ordering::Less)
                } else if val1 > val2 {
                    Some(Ordering::Greater)
                } else {
                    Some(Ordering::Equal)
                }
            }
            (VmValue::I64(val1), VmValue::I64(val2)) => {
                if val1 < val2 {
                    Some(Ordering::Less)
                } else if val1 > val2 {
                    Some(Ordering::Greater)
                } else {
                    Some(Ordering::Equal)
                }
            }
            (VmValue::F32(val1), VmValue::F32(val2)) => {
                if val1 < val2 {
                    Some(Ordering::Less)
                } else if val1 > val2 {
                    Some(Ordering::Greater)
                } else {
                    Some(Ordering::Equal)
                }
            }
            (VmValue::F64(val1), VmValue::F64(val2)) => {
                if val1 < val2 {
                    Some(Ordering::Less)
                } else if val1 > val2 {
                    Some(Ordering::Greater)
                } else {
                    Some(Ordering::Equal)
                }
            }
            (VmValue::i32Array2(_), VmValue::i32Array2(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i32Array4(_), VmValue::i32Array4(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i32Array8(_), VmValue::i32Array8(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i32Array16(_), VmValue::i32Array16(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i32Array32(_), VmValue::i32Array32(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i32Array64(_), VmValue::i32Array64(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i32Array128(_), VmValue::i32Array128(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i32Array256(_), VmValue::i32Array256(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i64Array2(_), VmValue::i64Array2(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i64Array4(_), VmValue::i64Array4(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i64Array8(_), VmValue::i64Array8(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i64Array16(_), VmValue::i64Array16(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i64Array32(_), VmValue::i64Array32(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i64Array64(_), VmValue::i64Array64(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i64Array128(_), VmValue::i64Array128(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::i64Array256(_), VmValue::i64Array256(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f32Array2(_), VmValue::f32Array2(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f32Array4(_), VmValue::f32Array4(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f32Array8(_), VmValue::f32Array8(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f32Array16(_), VmValue::f32Array16(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f32Array32(_), VmValue::f32Array32(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f32Array64(_), VmValue::f32Array64(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f32Array128(_), VmValue::f32Array128(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f32Array256(_), VmValue::f32Array256(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f64Array2(_), VmValue::f64Array2(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f64Array4(_), VmValue::f64Array4(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f64Array8(_), VmValue::f64Array8(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f64Array16(_), VmValue::f64Array16(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f64Array32(_), VmValue::f64Array32(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f64Array64(_), VmValue::f64Array64(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f64Array128(_), VmValue::f64Array128(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (VmValue::f64Array256(_), VmValue::f64Array256(_)) => {
                panic!("Cannot perform comparison between arrays!")
            }
            (_, _) => panic!("Cannot perform compare between different variants!"),
        }
    }
}

impl Add for VmValue {
    type Output = Result<VmValue, VmError>;

    // TODO: Possibly use native SIMD for arrays, but benchmark first
    fn add(self, other: VmValue) -> Result<VmValue, VmError> {
        match (self, other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => match val1.checked_add(val2) {
                Some(result) => Ok(VmValue::I32(result)),
                None => Err(VmError::Overflow),
            },
            (VmValue::I64(val1), VmValue::I64(val2)) => match val1.checked_add(val2) {
                Some(result) => Ok(VmValue::I64(result)),
                None => Err(VmError::Overflow),
            },
            (VmValue::F32(val1), VmValue::F32(val2)) => match VmValue::sum_f32(&val1, &val2) {
                Some(result) => Ok(VmValue::F32(result)),
                None => Err(VmError::Infinity),
            },
            (VmValue::F64(val1), VmValue::F64(val2)) => match VmValue::sum_f64(&val1, &val2) {
                Some(result) => Ok(VmValue::F64(result)),
                None => Err(VmError::Infinity),
            },
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_add(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(val1), VmValue::f32Array2(val2)) => {
                let mut result: [f32; 2] = [0.0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sum_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array2(result))
            }
            (VmValue::f32Array4(val1), VmValue::f32Array4(val2)) => {
                let mut result: [f32; 4] = [0.0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sum_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array4(result))
            }
            (VmValue::f32Array8(val1), VmValue::f32Array8(val2)) => {
                let mut result: [f32; 8] = [0.0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sum_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array8(result))
            }
            (VmValue::f32Array16(val1), VmValue::f32Array16(val2)) => {
                let mut result: [f32; 16] = [0.0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sum_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array16(result))
            }
            (VmValue::f32Array32(val1), VmValue::f32Array32(val2)) => {
                let mut result: [f32; 32] = [0.0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sum_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array32(result))
            }
            (VmValue::f32Array64(val1), VmValue::f32Array64(val2)) => {
                let mut result: [f32; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sum_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array64(result))
            }
            (VmValue::f32Array128(val1), VmValue::f32Array128(val2)) => {
                let mut result: [f32; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sum_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array128(result))
            }
            (VmValue::f32Array256(val1), VmValue::f32Array256(val2)) => {
                let mut result: [f32; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sum_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array256(result))
            }
            (VmValue::f64Array2(val1), VmValue::f64Array2(val2)) => {
                let mut result: [f64; 2] = [0.0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sum_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array2(result))
            }
            (VmValue::f64Array4(val1), VmValue::f64Array4(val2)) => {
                let mut result: [f64; 4] = [0.0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sum_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array4(result))
            }
            (VmValue::f64Array8(val1), VmValue::f64Array8(val2)) => {
                let mut result: [f64; 8] = [0.0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sum_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array8(result))
            }
            (VmValue::f64Array16(val1), VmValue::f64Array16(val2)) => {
                let mut result: [f64; 16] = [0.0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sum_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array16(result))
            }
            (VmValue::f64Array32(val1), VmValue::f64Array32(val2)) => {
                let mut result: [f64; 32] = [0.0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sum_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array32(result))
            }
            (VmValue::f64Array64(val1), VmValue::f64Array64(val2)) => {
                let mut result: [f64; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sum_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array64(result))
            }
            (VmValue::f64Array128(val1), VmValue::f64Array128(val2)) => {
                let mut result: [f64; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sum_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array128(result))
            }
            (VmValue::f64Array256(val1), VmValue::f64Array256(val2)) => {
                let mut result: [f64; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sum_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array256(result))
            }
            (_, _) => panic!("Cannot perform addition between different variants!"),
        }
    }
}

impl Sub for VmValue {
    type Output = Result<VmValue, VmError>;

    fn sub(self, other: VmValue) -> Result<VmValue, VmError> {
        match (self, other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => match val1.checked_sub(val2) {
                Some(result) => Ok(VmValue::I32(result)),
                None => Err(VmError::Overflow),
            },
            (VmValue::I64(val1), VmValue::I64(val2)) => match val1.checked_sub(val2) {
                Some(result) => Ok(VmValue::I64(result)),
                None => Err(VmError::Overflow),
            },
            (VmValue::F32(val1), VmValue::F32(val2)) => match VmValue::sub_f32(&val1, &val2) {
                Some(result) => Ok(VmValue::F32(result)),
                None => Err(VmError::Infinity),
            },
            (VmValue::F64(val1), VmValue::F64(val2)) => match VmValue::sub_f64(&val1, &val2) {
                Some(result) => Ok(VmValue::F64(result)),
                None => Err(VmError::Infinity),
            },
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_sub(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(val1), VmValue::f32Array2(val2)) => {
                let mut result: [f32; 2] = [0.0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sub_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array2(result))
            }
            (VmValue::f32Array4(val1), VmValue::f32Array4(val2)) => {
                let mut result: [f32; 4] = [0.0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sub_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array4(result))
            }
            (VmValue::f32Array8(val1), VmValue::f32Array8(val2)) => {
                let mut result: [f32; 8] = [0.0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sub_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array8(result))
            }
            (VmValue::f32Array16(val1), VmValue::f32Array16(val2)) => {
                let mut result: [f32; 16] = [0.0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sub_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array16(result))
            }
            (VmValue::f32Array32(val1), VmValue::f32Array32(val2)) => {
                let mut result: [f32; 32] = [0.0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sub_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array32(result))
            }
            (VmValue::f32Array64(val1), VmValue::f32Array64(val2)) => {
                let mut result: [f32; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sub_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array64(result))
            }
            (VmValue::f32Array128(val1), VmValue::f32Array128(val2)) => {
                let mut result: [f32; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sub_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array128(result))
            }
            (VmValue::f32Array256(val1), VmValue::f32Array256(val2)) => {
                let mut result: [f32; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sub_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array256(result))
            }
            (VmValue::f64Array2(val1), VmValue::f64Array2(val2)) => {
                let mut result: [f64; 2] = [0.0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sub_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array2(result))
            }
            (VmValue::f64Array4(val1), VmValue::f64Array4(val2)) => {
                let mut result: [f64; 4] = [0.0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sub_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array4(result))
            }
            (VmValue::f64Array8(val1), VmValue::f64Array8(val2)) => {
                let mut result: [f64; 8] = [0.0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sub_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array8(result))
            }
            (VmValue::f64Array16(val1), VmValue::f64Array16(val2)) => {
                let mut result: [f64; 16] = [0.0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sub_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array16(result))
            }
            (VmValue::f64Array32(val1), VmValue::f64Array32(val2)) => {
                let mut result: [f64; 32] = [0.0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::sub_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array32(result))
            }
            (VmValue::f64Array64(val1), VmValue::f64Array64(val2)) => {
                let mut result: [f64; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sub_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array64(result))
            }
            (VmValue::f64Array128(val1), VmValue::f64Array128(val2)) => {
                let mut result: [f64; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sub_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array128(result))
            }
            (VmValue::f64Array256(val1), VmValue::f64Array256(val2)) => {
                let mut result: [f64; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::sub_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array256(result))
            }
            (_, _) => panic!("Cannot perform substraction between different variants!"),
        }
    }
}

impl Mul for VmValue {
    type Output = Result<VmValue, VmError>;

    fn mul(self, other: VmValue) -> Result<VmValue, VmError> {
        match (self, other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => match val1.checked_mul(val2) {
                Some(result) => Ok(VmValue::I32(result)),
                None => Err(VmError::Overflow),
            },
            (VmValue::I64(val1), VmValue::I64(val2)) => match val1.checked_mul(val2) {
                Some(result) => Ok(VmValue::I64(result)),
                None => Err(VmError::Overflow),
            },
            (VmValue::F32(val1), VmValue::F32(val2)) => match VmValue::mul_f32(&val1, &val2) {
                Some(result) => Ok(VmValue::F32(result)),
                None => Err(VmError::Infinity),
            },
            (VmValue::F64(val1), VmValue::F64(val2)) => match VmValue::mul_f64(&val1, &val2) {
                Some(result) => Ok(VmValue::F64(result)),
                None => Err(VmError::Infinity),
            },
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_mul(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(val1), VmValue::f32Array2(val2)) => {
                let mut result: [f32; 2] = [0.0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::mul_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array2(result))
            }
            (VmValue::f32Array4(val1), VmValue::f32Array4(val2)) => {
                let mut result: [f32; 4] = [0.0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::mul_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array4(result))
            }
            (VmValue::f32Array8(val1), VmValue::f32Array8(val2)) => {
                let mut result: [f32; 8] = [0.0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::mul_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array8(result))
            }
            (VmValue::f32Array16(val1), VmValue::f32Array16(val2)) => {
                let mut result: [f32; 16] = [0.0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::mul_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array16(result))
            }
            (VmValue::f32Array32(val1), VmValue::f32Array32(val2)) => {
                let mut result: [f32; 32] = [0.0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::mul_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array32(result))
            }
            (VmValue::f32Array64(val1), VmValue::f32Array64(val2)) => {
                let mut result: [f32; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::mul_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array64(result))
            }
            (VmValue::f32Array128(val1), VmValue::f32Array128(val2)) => {
                let mut result: [f32; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::mul_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array128(result))
            }
            (VmValue::f32Array256(val1), VmValue::f32Array256(val2)) => {
                let mut result: [f32; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::mul_f32(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array256(result))
            }
            (VmValue::f64Array2(val1), VmValue::f64Array2(val2)) => {
                let mut result: [f64; 2] = [0.0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::mul_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array2(result))
            }
            (VmValue::f64Array4(val1), VmValue::f64Array4(val2)) => {
                let mut result: [f64; 4] = [0.0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::mul_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array4(result))
            }
            (VmValue::f64Array8(val1), VmValue::f64Array8(val2)) => {
                let mut result: [f64; 8] = [0.0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::mul_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array8(result))
            }
            (VmValue::f64Array16(val1), VmValue::f64Array16(val2)) => {
                let mut result: [f64; 16] = [0.0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::mul_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array16(result))
            }
            (VmValue::f64Array32(val1), VmValue::f64Array32(val2)) => {
                let mut result: [f64; 32] = [0.0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match VmValue::mul_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array32(result))
            }
            (VmValue::f64Array64(val1), VmValue::f64Array64(val2)) => {
                let mut result: [f64; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::mul_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array64(result))
            }
            (VmValue::f64Array128(val1), VmValue::f64Array128(val2)) => {
                let mut result: [f64; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::mul_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array128(result))
            }
            (VmValue::f64Array256(val1), VmValue::f64Array256(val2)) => {
                let mut result: [f64; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match VmValue::mul_f64(a, b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Infinity),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array256(result))
            }
            (_, _) => panic!("Cannot perform multiplication between different variants!"),
        }
    }
}

impl Div for VmValue {
    type Output = Result<VmValue, VmError>;

    fn div(self, other: VmValue) -> Result<VmValue, VmError> {
        match (self, other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => {
                if val2 == 0 {
                    return Err(VmError::DivideByZero);
                }

                match val1.checked_div(val2) {
                    Some(result) => Ok(VmValue::I32(result)),
                    None => Err(VmError::Overflow),
                }
            }
            (VmValue::I64(val1), VmValue::I64(val2)) => {
                if val2 == 0 {
                    return Err(VmError::DivideByZero);
                }

                match val1.checked_div(val2) {
                    Some(result) => Ok(VmValue::I64(result)),
                    None => Err(VmError::Overflow),
                }
            }
            (VmValue::F32(val1), VmValue::F32(val2)) => match VmValue::div_f32(&val1, &val2) {
                Ok(res) => Ok(VmValue::F32(res)),
                Err(err) => Err(err),
            },
            (VmValue::F64(val1), VmValue::F64(val2)) => match VmValue::div_f64(&val1, &val2) {
                Ok(res) => Ok(VmValue::F64(res)),
                Err(err) => Err(err),
            },
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_div(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(val1), VmValue::f32Array2(val2)) => {
                let mut result: [f32; 2] = [0.0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::div_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array2(result))
            }
            (VmValue::f32Array4(val1), VmValue::f32Array4(val2)) => {
                let mut result: [f32; 4] = [0.0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::div_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array4(result))
            }
            (VmValue::f32Array8(val1), VmValue::f32Array8(val2)) => {
                let mut result: [f32; 8] = [0.0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::div_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array8(result))
            }
            (VmValue::f32Array16(val1), VmValue::f32Array16(val2)) => {
                let mut result: [f32; 16] = [0.0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::div_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array16(result))
            }
            (VmValue::f32Array32(val1), VmValue::f32Array32(val2)) => {
                let mut result: [f32; 32] = [0.0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::div_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array32(result))
            }
            (VmValue::f32Array64(val1), VmValue::f32Array64(val2)) => {
                let mut result: [f32; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::div_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array64(result))
            }
            (VmValue::f32Array128(val1), VmValue::f32Array128(val2)) => {
                let mut result: [f32; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::div_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array128(result))
            }
            (VmValue::f32Array256(val1), VmValue::f32Array256(val2)) => {
                let mut result: [f32; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::div_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array256(result))
            }
            (VmValue::f64Array2(val1), VmValue::f64Array2(val2)) => {
                let mut result: [f64; 2] = [0.0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::div_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array2(result))
            }
            (VmValue::f64Array4(val1), VmValue::f64Array4(val2)) => {
                let mut result: [f64; 4] = [0.0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::div_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array4(result))
            }
            (VmValue::f64Array8(val1), VmValue::f64Array8(val2)) => {
                let mut result: [f64; 8] = [0.0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::div_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array8(result))
            }
            (VmValue::f64Array16(val1), VmValue::f64Array16(val2)) => {
                let mut result: [f64; 16] = [0.0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::div_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array16(result))
            }
            (VmValue::f64Array32(val1), VmValue::f64Array32(val2)) => {
                let mut result: [f64; 32] = [0.0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::div_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array32(result))
            }
            (VmValue::f64Array64(val1), VmValue::f64Array64(val2)) => {
                let mut result: [f64; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::div_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array64(result))
            }
            (VmValue::f64Array128(val1), VmValue::f64Array128(val2)) => {
                let mut result: [f64; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::div_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array128(result))
            }
            (VmValue::f64Array256(val1), VmValue::f64Array256(val2)) => {
                let mut result: [f64; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::div_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array256(result))
            }
            (_, _) => panic!("Cannot perform division between different variants!"),
        }
    }
}

impl Rem for VmValue {
    type Output = Result<VmValue, VmError>;

    fn rem(self, other: VmValue) -> Result<VmValue, VmError> {
        match (self, other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => {
                if val2 == 0 {
                    return Err(VmError::DivideByZero);
                }

                match val1.checked_rem(val2) {
                    Some(result) => Ok(VmValue::I32(result)),
                    None => Err(VmError::Overflow),
                }
            }
            (VmValue::I64(val1), VmValue::I64(val2)) => {
                if val2 == 0 {
                    return Err(VmError::DivideByZero);
                }

                match val1.checked_rem(val2) {
                    Some(result) => Ok(VmValue::I64(result)),
                    None => Err(VmError::Overflow),
                }
            }
            (VmValue::F32(val1), VmValue::F32(val2)) => match VmValue::rem_f32(&val1, &val2) {
                Ok(res) => Ok(VmValue::F32(res)),
                Err(err) => Err(err),
            },
            (VmValue::F64(val1), VmValue::F64(val2)) => match VmValue::rem_f64(&val1, &val2) {
                Ok(res) => Ok(VmValue::F64(res)),
                Err(err) => Err(err),
            },
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    if *b == 0 {
                        return Err(VmError::DivideByZero);
                    }

                    match a.checked_rem(*b) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(val1), VmValue::f32Array2(val2)) => {
                let mut result: [f32; 2] = [0.0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::rem_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array2(result))
            }
            (VmValue::f32Array4(val1), VmValue::f32Array4(val2)) => {
                let mut result: [f32; 4] = [0.0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::rem_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array4(result))
            }
            (VmValue::f32Array8(val1), VmValue::f32Array8(val2)) => {
                let mut result: [f32; 8] = [0.0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::rem_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array8(result))
            }
            (VmValue::f32Array16(val1), VmValue::f32Array16(val2)) => {
                let mut result: [f32; 16] = [0.0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::rem_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array16(result))
            }
            (VmValue::f32Array32(val1), VmValue::f32Array32(val2)) => {
                let mut result: [f32; 32] = [0.0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::rem_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array32(result))
            }
            (VmValue::f32Array64(val1), VmValue::f32Array64(val2)) => {
                let mut result: [f32; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::rem_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array64(result))
            }
            (VmValue::f32Array128(val1), VmValue::f32Array128(val2)) => {
                let mut result: [f32; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::rem_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array128(result))
            }
            (VmValue::f32Array256(val1), VmValue::f32Array256(val2)) => {
                let mut result: [f32; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::rem_f32(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f32Array256(result))
            }
            (VmValue::f64Array2(val1), VmValue::f64Array2(val2)) => {
                let mut result: [f64; 2] = [0.0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::rem_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array2(result))
            }
            (VmValue::f64Array4(val1), VmValue::f64Array4(val2)) => {
                let mut result: [f64; 4] = [0.0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::rem_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array4(result))
            }
            (VmValue::f64Array8(val1), VmValue::f64Array8(val2)) => {
                let mut result: [f64; 8] = [0.0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::rem_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array8(result))
            }
            (VmValue::f64Array16(val1), VmValue::f64Array16(val2)) => {
                let mut result: [f64; 16] = [0.0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::rem_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array16(result))
            }
            (VmValue::f64Array32(val1), VmValue::f64Array32(val2)) => {
                let mut result: [f64; 32] = [0.0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| VmValue::rem_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array32(result))
            }
            (VmValue::f64Array64(val1), VmValue::f64Array64(val2)) => {
                let mut result: [f64; 64] = [0.0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::rem_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array64(result))
            }
            (VmValue::f64Array128(val1), VmValue::f64Array128(val2)) => {
                let mut result: [f64; 128] = [0.0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::rem_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array128(result))
            }
            (VmValue::f64Array256(val1), VmValue::f64Array256(val2)) => {
                let mut result: [f64; 256] = [0.0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| VmValue::rem_f64(a, b));

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::f64Array256(result))
            }
            (_, _) => panic!("Cannot perform division between different variants!"),
        }
    }
}

impl Neg for VmValue {
    type Output = Result<VmValue, VmError>;

    fn neg(self) -> Result<VmValue, VmError> {
        match self {
            VmValue::I32(_) => Err(VmError::InvalidOperator),
            VmValue::I64(_) => Err(VmError::InvalidOperator),
            VmValue::F32(val) => Ok(VmValue::F32(-val)),
            VmValue::F64(val) => Ok(VmValue::F64(-val)),
            VmValue::i32Array2(_)
            | VmValue::i32Array4(_)
            | VmValue::i32Array8(_)
            | VmValue::i32Array16(_)
            | VmValue::i32Array32(_)
            | VmValue::i32Array64(_)
            | VmValue::i32Array128(_)
            | VmValue::i32Array256(_) => Err(VmError::InvalidOperator),
            VmValue::i64Array2(_)
            | VmValue::i64Array4(_)
            | VmValue::i64Array8(_)
            | VmValue::i64Array16(_)
            | VmValue::i64Array32(_)
            | VmValue::i64Array64(_)
            | VmValue::i64Array128(_)
            | VmValue::i64Array256(_) => Err(VmError::InvalidOperator),
            VmValue::f32Array2(val) => {
                let mut result: [f32; 2] = [0.0; 2];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f32Array2(result))
            }
            VmValue::f32Array4(val) => {
                let mut result: [f32; 4] = [0.0; 4];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f32Array4(result))
            }
            VmValue::f32Array8(val) => {
                let mut result: [f32; 8] = [0.0; 8];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f32Array8(result))
            }
            VmValue::f32Array16(val) => {
                let mut result: [f32; 16] = [0.0; 16];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f32Array16(result))
            }
            VmValue::f32Array32(val) => {
                let mut result: [f32; 32] = [0.0; 32];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f32Array32(result))
            }
            VmValue::f32Array64(val) => {
                let mut result: [f32; 64] = [0.0; 64];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f32Array64(result))
            }
            VmValue::f32Array128(val) => {
                let mut result: [f32; 128] = [0.0; 128];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f32Array128(result))
            }
            VmValue::f32Array256(val) => {
                let mut result: [f32; 256] = [0.0; 256];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f32Array256(result))
            }
            VmValue::f64Array2(val) => {
                let mut result: [f64; 2] = [0.0; 2];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f64Array2(result))
            }
            VmValue::f64Array4(val) => {
                let mut result: [f64; 4] = [0.0; 4];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f64Array4(result))
            }
            VmValue::f64Array8(val) => {
                let mut result: [f64; 8] = [0.0; 8];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f64Array8(result))
            }
            VmValue::f64Array16(val) => {
                let mut result: [f64; 16] = [0.0; 16];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f64Array16(result))
            }
            VmValue::f64Array32(val) => {
                let mut result: [f64; 32] = [0.0; 32];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f64Array32(result))
            }
            VmValue::f64Array64(val) => {
                let mut result: [f64; 64] = [0.0; 64];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f64Array64(result))
            }
            VmValue::f64Array128(val) => {
                let mut result: [f64; 128] = [0.0; 128];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f64Array128(result))
            }
            VmValue::f64Array256(val) => {
                let mut result: [f64; 256] = [0.0; 256];
                let negs = val.iter().map(|a| -a);
                for (r, v) in result.iter_mut().zip(negs) {
                    *r = v;
                }

                Ok(VmValue::f64Array256(result))
            }
        }
    }
}

impl BitAnd for VmValue {
    type Output = Result<VmValue, VmError>;

    fn bitand(self, other: VmValue) -> Result<VmValue, VmError> {
        match (self, other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => Ok(VmValue::I32(val1 & val2)),
            (VmValue::I64(val1), VmValue::I64(val2)) => Ok(VmValue::I64(val1 & val2)),
            (VmValue::F32(_), VmValue::F32(_)) => Err(VmError::InvalidOperator),
            (VmValue::F64(_), VmValue::F64(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a & b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(_), VmValue::f32Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array4(_), VmValue::f32Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array8(_), VmValue::f32Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array16(_), VmValue::f32Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array32(_), VmValue::f32Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array64(_), VmValue::f32Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array128(_), VmValue::f32Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array256(_), VmValue::f32Array256(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array2(_), VmValue::f64Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array4(_), VmValue::f64Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array8(_), VmValue::f64Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array16(_), VmValue::f64Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array32(_), VmValue::f64Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array64(_), VmValue::f64Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array128(_), VmValue::f64Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array256(_), VmValue::f64Array256(_)) => Err(VmError::InvalidOperator),
            (_, _) => panic!("Cannot perform bitand between different variants!"),
        }
    }
}

impl BitOr for VmValue {
    type Output = Result<VmValue, VmError>;

    fn bitor(self, other: VmValue) -> Result<VmValue, VmError> {
        match (self, other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => Ok(VmValue::I32(val1 | val2)),
            (VmValue::I64(val1), VmValue::I64(val2)) => Ok(VmValue::I64(val1 | val2)),
            (VmValue::F32(_), VmValue::F32(_)) => Err(VmError::InvalidOperator),
            (VmValue::F64(_), VmValue::F64(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a | b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(_), VmValue::f32Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array4(_), VmValue::f32Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array8(_), VmValue::f32Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array16(_), VmValue::f32Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array32(_), VmValue::f32Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array64(_), VmValue::f32Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array128(_), VmValue::f32Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array256(_), VmValue::f32Array256(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array2(_), VmValue::f64Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array4(_), VmValue::f64Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array8(_), VmValue::f64Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array16(_), VmValue::f64Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array32(_), VmValue::f64Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array64(_), VmValue::f64Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array128(_), VmValue::f64Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array256(_), VmValue::f64Array256(_)) => Err(VmError::InvalidOperator),
            (_, _) => panic!("Cannot perform bitor between different variants!"),
        }
    }
}

impl BitXor for VmValue {
    type Output = Result<VmValue, VmError>;

    fn bitxor(self, other: VmValue) -> Result<VmValue, VmError> {
        match (self, other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => Ok(VmValue::I32(val1 ^ val2)),
            (VmValue::I64(val1), VmValue::I64(val2)) => Ok(VmValue::I64(val1 ^ val2)),
            (VmValue::F32(_), VmValue::F32(_)) => Err(VmError::InvalidOperator),
            (VmValue::F64(_), VmValue::F64(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1.iter().zip(&val2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1.iter().zip(&val2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1.iter().zip(&val2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1.iter().zip(&val2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1.iter().zip(&val2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| a ^ b);
                for (r, v) in result.iter_mut().zip(src) {
                    *r = v;
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(_), VmValue::f32Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array4(_), VmValue::f32Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array8(_), VmValue::f32Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array16(_), VmValue::f32Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array32(_), VmValue::f32Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array64(_), VmValue::f32Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array128(_), VmValue::f32Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array256(_), VmValue::f32Array256(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array2(_), VmValue::f64Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array4(_), VmValue::f64Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array8(_), VmValue::f64Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array16(_), VmValue::f64Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array32(_), VmValue::f64Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array64(_), VmValue::f64Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array128(_), VmValue::f64Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array256(_), VmValue::f64Array256(_)) => Err(VmError::InvalidOperator),
            (_, _) => panic!("Cannot perform bitxor between different variants!"),
        }
    }
}

impl Shl for VmValue {
    type Output = Result<VmValue, VmError>;

    fn shl(self, other: VmValue) -> Result<VmValue, VmError> {
        match (self, other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => match val1.checked_shl(val2 as u32) {
                Some(result) => Ok(VmValue::I32(result)),
                None => Err(VmError::Overflow),
            },
            (VmValue::I64(val1), VmValue::I64(val2)) => match val1.checked_shl(val2 as u32) {
                Some(result) => Ok(VmValue::I64(result)),
                None => Err(VmError::Overflow),
            },
            (VmValue::F32(_), VmValue::F32(_)) => Err(VmError::InvalidOperator),
            (VmValue::F64(_), VmValue::F64(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shl(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(_), VmValue::f32Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array4(_), VmValue::f32Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array8(_), VmValue::f32Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array16(_), VmValue::f32Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array32(_), VmValue::f32Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array64(_), VmValue::f32Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array128(_), VmValue::f32Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array256(_), VmValue::f32Array256(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array2(_), VmValue::f64Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array4(_), VmValue::f64Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array8(_), VmValue::f64Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array16(_), VmValue::f64Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array32(_), VmValue::f64Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array64(_), VmValue::f64Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array128(_), VmValue::f64Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array256(_), VmValue::f64Array256(_)) => Err(VmError::InvalidOperator),
            (_, _) => panic!("Cannot perform shl between different variants!"),
        }
    }
}

impl Shr for VmValue {
    type Output = Result<VmValue, VmError>;

    fn shr(self, other: VmValue) -> Result<VmValue, VmError> {
        match (self, other) {
            (VmValue::I32(val1), VmValue::I32(val2)) => match val1.checked_shr(val2 as u32) {
                Some(result) => Ok(VmValue::I32(result)),
                None => Err(VmError::Overflow),
            },
            (VmValue::I64(val1), VmValue::I64(val2)) => match val1.checked_shr(val2 as u32) {
                Some(result) => Ok(VmValue::I64(result)),
                None => Err(VmError::Overflow),
            },
            (VmValue::F32(_), VmValue::F32(_)) => Err(VmError::InvalidOperator),
            (VmValue::F64(_), VmValue::F64(_)) => Err(VmError::InvalidOperator),
            (VmValue::i32Array2(val1), VmValue::i32Array2(val2)) => {
                let mut result: [i32; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array2(result))
            }
            (VmValue::i32Array4(val1), VmValue::i32Array4(val2)) => {
                let mut result: [i32; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array4(result))
            }
            (VmValue::i32Array8(val1), VmValue::i32Array8(val2)) => {
                let mut result: [i32; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array8(result))
            }
            (VmValue::i32Array16(val1), VmValue::i32Array16(val2)) => {
                let mut result: [i32; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array16(result))
            }
            (VmValue::i32Array32(val1), VmValue::i32Array32(val2)) => {
                let mut result: [i32; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array32(result))
            }
            (VmValue::i32Array64(val1), VmValue::i32Array64(val2)) => {
                let mut result: [i32; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array64(result))
            }
            (VmValue::i32Array128(val1), VmValue::i32Array128(val2)) => {
                let mut result: [i32; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array128(result))
            }
            (VmValue::i32Array256(val1), VmValue::i32Array256(val2)) => {
                let mut result: [i32; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i32Array256(result))
            }
            (VmValue::i64Array2(val1), VmValue::i64Array2(val2)) => {
                let mut result: [i64; 2] = [0; 2];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array2(result))
            }
            (VmValue::i64Array4(val1), VmValue::i64Array4(val2)) => {
                let mut result: [i64; 4] = [0; 4];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array4(result))
            }
            (VmValue::i64Array8(val1), VmValue::i64Array8(val2)) => {
                let mut result: [i64; 8] = [0; 8];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array8(result))
            }
            (VmValue::i64Array16(val1), VmValue::i64Array16(val2)) => {
                let mut result: [i64; 16] = [0; 16];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array16(result))
            }
            (VmValue::i64Array32(val1), VmValue::i64Array32(val2)) => {
                let mut result: [i64; 32] = [0; 32];
                let src = val1
                    .iter()
                    .zip(&val2)
                    .map(|(a, b)| match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array32(result))
            }
            (VmValue::i64Array64(val1), VmValue::i64Array64(val2)) => {
                let mut result: [i64; 64] = [0; 64];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array64(result))
            }
            (VmValue::i64Array128(val1), VmValue::i64Array128(val2)) => {
                let mut result: [i64; 128] = [0; 128];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array128(result))
            }
            (VmValue::i64Array256(val1), VmValue::i64Array256(val2)) => {
                let mut result: [i64; 256] = [0; 256];
                let v1 = val1.to_vec();
                let v2 = val2.to_vec();
                let src = v1.iter().zip(&v2).map(|(a, b)| {
                    match a.checked_shr(*b as u32) {
                        Some(res) => Ok(res),
                        None => Err(VmError::Overflow),
                    }
                });

                for (r, v) in result.iter_mut().zip(src) {
                    match v {
                        Ok(res) => *r = res,
                        Err(err) => return Err(err),
                    };
                }

                Ok(VmValue::i64Array256(result))
            }
            (VmValue::f32Array2(_), VmValue::f32Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array4(_), VmValue::f32Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array8(_), VmValue::f32Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array16(_), VmValue::f32Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array32(_), VmValue::f32Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array64(_), VmValue::f32Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array128(_), VmValue::f32Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f32Array256(_), VmValue::f32Array256(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array2(_), VmValue::f64Array2(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array4(_), VmValue::f64Array4(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array8(_), VmValue::f64Array8(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array16(_), VmValue::f64Array16(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array32(_), VmValue::f64Array32(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array64(_), VmValue::f64Array64(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array128(_), VmValue::f64Array128(_)) => Err(VmError::InvalidOperator),
            (VmValue::f64Array256(_), VmValue::f64Array256(_)) => Err(VmError::InvalidOperator),
            (_, _) => panic!("Cannot perform shr between different variants!"),
        }
    }
}

impl fmt::Debug for VmValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VmValue::I32(val) => write!(f, "{}", val),
            VmValue::I64(val) => write!(f, "{}", val),
            VmValue::F32(val) => write!(f, "{}", val),
            VmValue::F64(val) => write!(f, "{}", val),
            VmValue::i32Array2(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i32Array4(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i32Array8(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i32Array16(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i32Array32(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i32Array64(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i32Array128(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i32Array256(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i64Array2(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i64Array4(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i64Array8(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i64Array16(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i64Array32(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i64Array64(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i64Array128(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::i64Array256(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f32Array2(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f32Array4(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f32Array8(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f32Array16(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f32Array32(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f32Array64(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f32Array128(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f32Array256(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f64Array2(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f64Array4(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f64Array8(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f64Array16(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f64Array32(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f64Array64(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f64Array128(val) => write!(f, "{:?}", val.to_vec()),
            VmValue::f64Array256(val) => write!(f, "{:?}", val.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[rustfmt::skip]
    fn it_returns_error_on_overflow_array() {
        let arr1: VmValue = VmValue::i32Array2([0, 2147483647]);
        let arr2: VmValue = VmValue::i32Array2([10, 1]);
        assert_eq!(arr1 + arr2, Err(VmError::Overflow));

        let arr1: VmValue = VmValue::i32Array4([0, 0, 2147483647, 0]);
        let arr2: VmValue = VmValue::i32Array4([10, 2, 1, 0]);
        assert_eq!(arr1 + arr2, Err(VmError::Overflow));

        let arr1: VmValue = VmValue::i32Array8([0, 0, 2147483647, 0, 0, 0, 2147483647, 0]);
        let arr2: VmValue = VmValue::i32Array8([10, 2, 1, 0, 10, 2, 1, 0]);
        assert_eq!(arr1 + arr2, Err(VmError::Overflow));
    }

    #[test]
    #[rustfmt::skip]
    fn it_returns_error_on_divide_by_zero() {
        let val1: VmValue = VmValue::I32(10);
        let val2: VmValue = VmValue::I32(0);
        assert_eq!(val1 / val2, Err(VmError::DivideByZero));

        let arr1: VmValue = VmValue::i32Array4([10, 20, 2147483647, 0]);
        let arr2: VmValue = VmValue::i32Array4([10, 2, 1, 0]);
        assert_eq!(arr1 / arr2, Err(VmError::DivideByZero));

        let arr1: VmValue = VmValue::i32Array8([10, 0, 2147483647, 20, 30, 40, 2147483647, 0]);
        let arr2: VmValue = VmValue::i32Array8([10, 2, 1, 0, 10, 2, 1, 10]);
        assert_eq!(arr1 / arr2, Err(VmError::DivideByZero));
    }

    #[test]
    #[rustfmt::skip]
    fn it_returns_error_on_remainder_by_zero() {
        let val1: VmValue = VmValue::I32(10);
        let val2: VmValue = VmValue::I32(0);
        assert_eq!(val1 % val2, Err(VmError::DivideByZero));

        let arr1: VmValue = VmValue::i32Array4([10, 20, 2147483647, 0]);
        let arr2: VmValue = VmValue::i32Array4([10, 2, 1, 0]);
        assert_eq!(arr1 % arr2, Err(VmError::DivideByZero));

        let arr1: VmValue = VmValue::i32Array8([10, 0, 2147483647, 20, 30, 40, 2147483647, 0]);
        let arr2: VmValue = VmValue::i32Array8([10, 2, 1, 0, 10, 2, 1, 10]);
        assert_eq!(arr1 % arr2, Err(VmError::DivideByZero));
    }
}
