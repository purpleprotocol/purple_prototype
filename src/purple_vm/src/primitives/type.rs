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

#[derive(Clone, Debug, Copy)]
pub enum VmType {
    I32,
    I64,
    F32,
    F64,
    i32Array2,
    i32Array4,
    i32Array8,
    i32Array16,
    i32Array32,
    i32Array64,
    i32Array128,
    i32Array256,
    i64Array2,
    i64Array4,
    i64Array8,
    i64Array16,
    i64Array32,
    i64Array64,
    i64Array128,
    i64Array256,
    f32Array2,
    f32Array4,
    f32Array8,
    f32Array16,
    f32Array32,
    f32Array64,
    f32Array128,
    f32Array256,
    f64Array2,
    f64Array4,
    f64Array8,
    f64Array16,
    f64Array32,
    f64Array64,
    f64Array128,
    f64Array256,
}

impl VmType {
    pub fn from_op(op: u8) -> Option<VmType> {
        match Instruction::from_repr(op) {
            Some(Instruction::i32Const)     => Some(VmType::I32),
            Some(Instruction::i64Const)     => Some(VmType::I64),
            Some(Instruction::f32Const)     => Some(VmType::F32),
            Some(Instruction::f64Const)     => Some(VmType::F64),
            Some(Instruction::i32Array2)    => Some(VmType::i32Array2),
            Some(Instruction::i32Array4)    => Some(VmType::i32Array4),
            Some(Instruction::i32Array8)    => Some(VmType::i32Array8),
            Some(Instruction::i32Array16)   => Some(VmType::i32Array16),
            Some(Instruction::i32Array32)   => Some(VmType::i32Array32),
            Some(Instruction::i32Array64)   => Some(VmType::i32Array64),
            Some(Instruction::i32Array128)  => Some(VmType::i32Array128),
            Some(Instruction::i32Array256)  => Some(VmType::i32Array256),
            Some(Instruction::i64Array2)    => Some(VmType::i64Array2),
            Some(Instruction::i64Array4)    => Some(VmType::i64Array4),
            Some(Instruction::i64Array8)    => Some(VmType::i64Array8),
            Some(Instruction::i64Array16)   => Some(VmType::i64Array16),
            Some(Instruction::i64Array32)   => Some(VmType::i64Array32),
            Some(Instruction::i64Array64)   => Some(VmType::i64Array64),
            Some(Instruction::i64Array128)  => Some(VmType::i64Array128),
            Some(Instruction::i64Array256)  => Some(VmType::i64Array256),
            Some(Instruction::f32Array2)    => Some(VmType::f32Array2),
            Some(Instruction::f32Array4)    => Some(VmType::f32Array4),
            Some(Instruction::f32Array8)    => Some(VmType::f32Array8),
            Some(Instruction::f32Array16)   => Some(VmType::f32Array16),
            Some(Instruction::f32Array32)   => Some(VmType::f32Array32),
            Some(Instruction::f32Array64)   => Some(VmType::f32Array64),
            Some(Instruction::f32Array128)  => Some(VmType::f32Array128),
            Some(Instruction::f32Array256)  => Some(VmType::f32Array256),
            Some(Instruction::f64Array2)    => Some(VmType::f64Array2),
            Some(Instruction::f64Array4)    => Some(VmType::f64Array4),
            Some(Instruction::f64Array8)    => Some(VmType::f64Array8),
            Some(Instruction::f64Array16)   => Some(VmType::f64Array16),
            Some(Instruction::f64Array32)   => Some(VmType::f64Array32),
            Some(Instruction::f64Array64)   => Some(VmType::f64Array64),
            Some(Instruction::f64Array128)  => Some(VmType::f64Array128),
            Some(Instruction::f64Array256)  => Some(VmType::f64Array256),
            _                               => None
        }
    }
}