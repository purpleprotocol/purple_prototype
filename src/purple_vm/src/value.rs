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

#[derive(Clone, Debug)]
pub enum VmValue {
    I32,
    I64,
    F32,
    F64
}

impl VmValue {
    pub fn from_op(op: u8) -> Option<VmValue> {
        match Instruction::from_repr(op) {
            Some(Instruction::i32Const) => Some(VmValue::I32),
            Some(Instruction::i64Const) => Some(VmValue::I64),
            Some(Instruction::f32Const) => Some(VmValue::F32),
            Some(Instruction::f64Const) => Some(VmValue::F64),
            _                           => None
        }
    }
}