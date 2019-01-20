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

#[EnumRepr(type = "u8")]
#[derive(Debug)]
pub enum Instruction {
    Halt                  = 0x00,
    Nop                   = 0x01,
    Block                 = 0x02,
    Loop                  = 0x03,
    If                    = 0x04,
    Else                  = 0x05,
    End                   = 0x06,
    Break                 = 0x07,
    BreakIf               = 0x08,
    Return                = 0x09,
    Call                  = 0x0a,

    // Local variables
    GetLocal              = 0x10,
    SetLocal              = 0x11,
    TeeLocal              = 0x12,

    // State
    GetState              = 0x13,
    SetState              = 0x14,

    // Memory load
    i32Load               = 0x15,
    i64Load               = 0x16,
    f32Load               = 0x17,
    f64Load               = 0x18,
    i32Load8Signed        = 0x19,
    i32Load8Unsigned      = 0x1a,
    i32Load16Signed       = 0x1b,
    i32Load16Unsigned     = 0x1c,
    i64Load8Signed        = 0x1d,
    i64Load8Unsigned      = 0x1e,
    i64Load16Signed       = 0x1f,
    i64Load16Unsigned     = 0x20,
    i64Load32Signed       = 0x21,
    i64Load32Unsigned     = 0x22,

    // Memory store 
    i32Store              = 0x23,
    i64Store              = 0x24,
    f32Store              = 0x25,
    f64Store              = 0x26,
    i32Store8             = 0x27,
    i32Store16            = 0x28,
    i64Store8             = 0x29,
    i64Store16            = 0x2a,
    i64Store32            = 0x2b,

    // i32 operations
    i32Add                = 0x30,
    i32Sub                = 0x31,
    i32Mul                = 0x32,
    i32DivSigned          = 0x33,
    i32DivUnsigned        = 0x34,
    i32RemSigned          = 0x35,
    i32RemUnsigned        = 0x36,
    i32And                = 0x37,
    i32Or                 = 0x38,
    i32Xor                = 0x39,
    i32Shl                = 0x3a,
    i32ShrSigned          = 0x3b,
    i32ShrUnsigned        = 0x3c,
    i32Rotl               = 0x3d,
    i32Rotr               = 0x3f,

    // i64 operations
    i64Add                = 0x40,
    i64Sub                = 0x41,
    i64Mul                = 0x42,
    i64DivSigned          = 0x43,
    i64DivUnsigned        = 0x44,
    i64RemSigned          = 0x45,
    i64RemUnsigned        = 0x46,
    i64And                = 0x47,
    i64Or                 = 0x48,
    i64Xor                = 0x49,
    i64Shl                = 0x4a,
    i64ShrSigned          = 0x4b,
    i64SHrUnsigned        = 0x4c,
    i64Rotl               = 0x4d,
    i64Rotr               = 0x4f,

    // f32 operations
    f32Abs                = 0x50,
    f32Neg                = 0x51,
    f32Add                = 0x52,
    f32Sub                = 0x53,
    f32Div                = 0x54,
    f32Ceil               = 0x55,
    f32Floor              = 0x56,
    f32Trunc              = 0x57,
    f32Nearest            = 0x58,
    f32CopySign           = 0x59,
    f32Sqrt               = 0x5a,
    f32Min                = 0x5b,
    f32Max                = 0x5c,

    // f64 operations 
    f64Abs                = 0x60,
    f64Neg                = 0x61,
    f64Add                = 0x62,
    f64Sub                = 0x63,
    f64Div                = 0x64,
    f64Ceil               = 0x65,
    f64Floor              = 0x66,
    f64Trunc              = 0x67,
    f64Nearest            = 0x68,
    f64CopySign           = 0x69,
    f64Sqrt               = 0x6a,
    f64Min                = 0x6b,
    f64Max                = 0x6c,

    // i32 comparison operators
    i32Eqz                = 0x70,
    i32Eq                 = 0x71,
    i32Ne                 = 0x73,
    i32LtSigned           = 0x74,
    i32LtUnsigned         = 0x75,
    i32GtSigned           = 0x76,
    i32GtUnsigned         = 0x77,
    i32LeSigned           = 0x78,
    i32LeUnsigned         = 0x79,
    i32GeSigned           = 0x7a,
    i32GeUnsigned         = 0x7b,

    // i64 comparison operators
    i64Eqz                = 0x80,
    i64Eq                 = 0x81,
    i64Ne                 = 0x83,
    i64LtSigned           = 0x84,
    i64LtUnsigned         = 0x85,
    i64GtSigned           = 0x86,
    i64GtUnsigned         = 0x87,
    i64LeSigned           = 0x88,
    i64LeUnsigned         = 0x89,
    i64GeSigned           = 0x8a,
    i64GeUnsigned         = 0x8b,

    // f32 comparison operators
    f32Eqz                = 0x90,
    f32Eq                 = 0x91,
    f32Ne                 = 0x93,
    f32LtSigned           = 0x94,
    f32LtUnsigned         = 0x95,
    f32GtSigned           = 0x96,
    f32GtUnsigned         = 0x97,
    f32LeSigned           = 0x98,
    f32LeUnsigned         = 0x99,
    f32GeSigned           = 0x9a,
    f32GeUnsigned         = 0x9b,

    // f64 comparison operators
    f64Eqz                = 0xa0,
    f64Eq                 = 0xa1,
    f64Ne                 = 0xa3,
    f64LtSigned           = 0xa4,
    f64LtUnsigned         = 0xa5,
    f64GtSigned           = 0xa6,
    f64GtUnsigned         = 0xa7,
    f64LeSigned           = 0xa8,
    f64LeUnsigned         = 0xa9,
    f64GeSigned           = 0xaa,
    f64GeUnsigned         = 0xab,

    // Constants
    i32Const              = 0xb0,
    i64Const              = 0xb1,
    f32Const              = 0xb2,
    f64Const              = 0xb3,

    // Datatype conversions
    i32Wrapi64            = 0xb5,
    i32TruncSignedf32     = 0xb6,
    i32TrunsUnsignedf32   = 0xb7,
    i32TruncSignedf64     = 0xb8,
    i32TruncUnsignedf64   = 0xb9,
    i64ExtendSignedi32    = 0xba,
    i64ExtendUnsignedi32  = 0xbb,
    i64TruncSignedf32     = 0xbc,
    i64TruncUnsignedf32   = 0xbd,
    i64TruncSignedf64     = 0xbe,
    i64TruncUnsignedf64   = 0xbf,
    f32ConvertSignedi32   = 0xc0,
    f32ConvertUnsignedi32 = 0xc1,
    f32ConvertSignedi64   = 0xc2,
    f32ConvertUnsignedi64 = 0xc3,
    f32Demotef64          = 0xc4,
    f64ConvertSignedi32   = 0xc5,
    f64ConvertUnsignedi32 = 0xc6,
    f64ConvertSignedi64   = 0xc7,
    f64ConvertUnsignedi64 = 0xc8,
    f64Promotef32         = 0xc9,
    i32Reinterpretf32     = 0xca,
    i64Reinterpretf64     = 0xcb,
    f32Reinterpreti32     = 0xcc,
    f64Reinterpreti64     = 0xcd,

    // Vm interface
    GcStart               = 0xd0,

    // Blockchain api
    GetBalance            = 0xe0,
    SendCurrency          = 0xe1,
    Mint                  = 0xe2,
    Burn                  = 0xe3,
    CreateContract        = 0xe4,
    CreateCurrency        = 0xe5,
    CreateMintable        = 0xe6,
    CallerAddress         = 0xe7,
    CallCurrency          = 0xe8,
    RandomNumber          = 0xe9,
    CurrentTime           = 0xea,
    Suicide               = 0xff
}