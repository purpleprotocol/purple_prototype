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
    I32Array2,
    I32Array4,
    I32Array8,
    I32Array16,
    I32Array32,
    I32Array64,
    I32Array128,
    I32Array256,
    I64Array2,
    I64Array4,
    I64Array8,
    I64Array16,
    I64Array32,
    I64Array64,
    I64Array128,
    I64Array256,
    F32Array2,
    F32Array4,
    F32Array8,
    F32Array16,
    F32Array32,
    F32Array64,
    F32Array128,
    F32Array256,
    F64Array2,
    F64Array4,
    F64Array8,
    F64Array16,
    F64Array32,
    F64Array64,
    F64Array128,
    F64Array256,
}

impl VmType {
    pub fn from_op(op: u8) -> Option<VmType> {
        match Instruction::from_repr(op) {
            Some(Instruction::i32Const)     => Some(VmType::I32),
            Some(Instruction::i64Const)     => Some(VmType::I64),
            Some(Instruction::f32Const)     => Some(VmType::F32),
            Some(Instruction::f64Const)     => Some(VmType::F64),
            Some(Instruction::i32Array2)    => Some(VmType::I32Array2),
            Some(Instruction::i32Array4)    => Some(VmType::I32Array4),
            Some(Instruction::i32Array8)    => Some(VmType::I32Array8),
            Some(Instruction::i32Array16)   => Some(VmType::I32Array16),
            Some(Instruction::i32Array32)   => Some(VmType::I32Array32),
            Some(Instruction::i32Array64)   => Some(VmType::I32Array64),
            Some(Instruction::i32Array128)  => Some(VmType::I32Array128),
            Some(Instruction::i32Array256)  => Some(VmType::I32Array256),
            Some(Instruction::i64Array2)    => Some(VmType::I64Array2),
            Some(Instruction::i64Array4)    => Some(VmType::I64Array4),
            Some(Instruction::i64Array8)    => Some(VmType::I64Array8),
            Some(Instruction::i64Array16)   => Some(VmType::I64Array16),
            Some(Instruction::i64Array32)   => Some(VmType::I64Array32),
            Some(Instruction::i64Array64)   => Some(VmType::I64Array64),
            Some(Instruction::i64Array128)  => Some(VmType::I64Array128),
            Some(Instruction::i64Array256)  => Some(VmType::I64Array256),
            Some(Instruction::f32Array2)    => Some(VmType::F32Array2),
            Some(Instruction::f32Array4)    => Some(VmType::F32Array4),
            Some(Instruction::f32Array8)    => Some(VmType::F32Array8),
            Some(Instruction::f32Array16)   => Some(VmType::F32Array16),
            Some(Instruction::f32Array32)   => Some(VmType::F32Array32),
            Some(Instruction::f32Array64)   => Some(VmType::F32Array64),
            Some(Instruction::f32Array128)  => Some(VmType::F32Array128),
            Some(Instruction::f32Array256)  => Some(VmType::F32Array256),
            Some(Instruction::f64Array2)    => Some(VmType::F64Array2),
            Some(Instruction::f64Array4)    => Some(VmType::F64Array4),
            Some(Instruction::f64Array8)    => Some(VmType::F64Array8),
            Some(Instruction::f64Array16)   => Some(VmType::F64Array16),
            Some(Instruction::f64Array32)   => Some(VmType::F64Array32),
            Some(Instruction::f64Array64)   => Some(VmType::F64Array64),
            Some(Instruction::f64Array128)  => Some(VmType::F64Array128),
            Some(Instruction::f64Array256)  => Some(VmType::F64Array256),
            _                               => None
        }
    }
}