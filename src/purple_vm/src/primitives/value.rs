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

use instruction_set::Instruction;
use std::fmt;

#[derive(Clone, Copy)]
pub enum VmValue {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    I32Array2([i32; 2]),
    I32Array4([i32; 4]),
    I32Array8([i32; 8]),
    I32Array16([i32; 16]),
    I32Array32([i32; 32]),
    I32Array64([i32; 64]),
    I32Array128([i32; 128]),
    I32Array256([i32; 256]),
    I64Array2([i64; 2]),
    I64Array4([i64; 4]),
    I64Array8([i64; 8]),
    I64Array16([i64; 16]),
    I64Array32([i64; 32]),
    I64Array64([i64; 64]),
    I64Array128([i64; 128]),
    I64Array256([i64; 256]),
    F32Array2([f32; 2]),
    F32Array4([f32; 4]),
    F32Array8([f32; 8]),
    F32Array16([f32; 16]),
    F32Array32([f32; 32]),
    F32Array64([f32; 64]),
    F32Array128([f32; 128]),
    F32Array256([f32; 256]),
    F64Array2([f64; 2]),
    F64Array4([f64; 4]),
    F64Array8([f64; 8]),
    F64Array16([f64; 16]),
    F64Array32([f64; 32]),
    F64Array64([f64; 64]),
    F64Array128([f64; 128]),
    F64Array256([f64; 256]),
}

impl fmt::Debug for VmValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VmValue::I32(val) => write!(f, "{}", val),
            VmValue::I64(val) => write!(f, "{}", val),
            VmValue::F32(val) => write!(f, "{}", val),
            VmValue::F64(val) => write!(f, "{}", val),
            VmValue::I32Array2(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I32Array4(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I32Array8(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I32Array16(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I32Array32(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I32Array64(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I32Array128(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I32Array256(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I64Array2(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I64Array4(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I64Array8(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I64Array16(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I64Array32(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I64Array64(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I64Array128(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::I64Array256(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F32Array2(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F32Array4(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F32Array8(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F32Array16(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F32Array32(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F32Array64(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F32Array128(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F32Array256(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F64Array2(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F64Array4(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F64Array8(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F64Array16(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F64Array32(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F64Array64(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F64Array128(val) => {
                write!(f, "{:?}", val.to_vec())
            },
            VmValue::F64Array256(val) => {
                write!(f, "{:?}", val.to_vec())
            }
        }   
    }
}
