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
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Instruction {
    Halt                  = 0x00,
    Nop                   = 0x01,
    Begin                 = 0x02,
    Loop                  = 0x03,
    If                    = 0x04,
    Else                  = 0x05,
    End                   = 0x06,
    Break                 = 0x07,
    BreakIf               = 0x08,
    Return                = 0x09,
    Call                  = 0x0a,

    // Local stack
    PushLocal             = 0x0b,
    PopLocal              = 0x0c,
    PickLocal             = 0x0d,
    PeekLocal             = 0x0e,

    // Operand stack 
    PushOperand           = 0x10,
    PopOperand            = 0x11,
    PeekOperand           = 0x12,

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

    // Array operations 
    Fetch                 = 0x2c,
    Grow                  = 0x2d,
    ArrayPush             = 0x2e,
    ArrayPop              = 0x2f,

    // Common operations
    Add                   = 0x30,
    Sub                   = 0x31,
    Mul                   = 0x32,
    DivSigned             = 0x33,
    DivUnsigned           = 0x34,
    RemSigned             = 0x35,
    RemUnsigned           = 0x36,
    Min                   = 0x37,
    Max                   = 0x38,

    // Integer only common operations
    And                   = 0x39,
    Or                    = 0x3a,
    Xor                   = 0x3b,
    Shl                   = 0x3c,
    ShrSigned             = 0x3d,
    ShrUnsigned           = 0x3e,
    Rotl                  = 0x3f,
    Rotr                  = 0x40,

    // Float only common operations
    Abs                   = 0x41,
    Neg                   = 0x42,
    Div                   = 0x43,
    Ceil                  = 0x44,
    Floor                 = 0x45,
    Trunc                 = 0x46,
    Nearest               = 0x47,
    CopySign              = 0x48,
    Sqrt                  = 0x49,

    // Comparison operators
    Eqz                   = 0x4a,
    Eq                    = 0x4b,
    Ne                    = 0x4c,
    LtSigned              = 0x4d,
    LtUnsigned            = 0x4e,
    GtSigned              = 0x4f,
    GtUnsigned            = 0x50,
    LeSigned              = 0x51,
    LeUnsigned            = 0x52,
    GeSigned              = 0x53,
    GeUnsigned            = 0x54,

    // Constants
    i32Const              = 0x60,
    i64Const              = 0x61,
    f32Const              = 0x62,
    f64Const              = 0x63,
    i32Array2             = 0x64,
    i32Array4             = 0x65,
    i32Array8             = 0x66,
    i32Array16            = 0x67,
    i32Array32            = 0x68,
    i32Array64            = 0x69,
    i32Array128           = 0x6a,
    i32Array256           = 0x6c,
    i64Array2             = 0x6d,
    i64Array4             = 0x6e,
    i64Array8             = 0x6f,
    i64Array16            = 0x70,
    i64Array32            = 0x71,
    i64Array64            = 0x72,
    i64Array128           = 0x73,
    i64Array256           = 0x74,
    f32Array2             = 0x76,
    f32Array4             = 0x77,
    f32Array8             = 0x78,
    f32Array16            = 0x79,
    f32Array32            = 0x7a,
    f32Array64            = 0x7b,
    f32Array128           = 0x7c,
    f32Array256           = 0x7d,
    f64Array2             = 0x7e,
    f64Array4             = 0x7f,
    f64Array8             = 0x80,
    f64Array16            = 0x81,
    f64Array32            = 0x82,
    f64Array64            = 0x83,
    f64Array128           = 0x84,
    f64Array256           = 0x85,

    // Datatype conversions
    i32Wrapi64            = 0x86,
    i32TruncSignedf32     = 0x87,
    i32TrunsUnsignedf32   = 0x88,
    i32TruncSignedf64     = 0x89,
    i32TruncUnsignedf64   = 0x8a,
    i64ExtendSignedi32    = 0x8b,
    i64ExtendUnsignedi32  = 0x8c,
    i64TruncSignedf32     = 0x8d,
    i64TruncUnsignedf32   = 0x8f,
    i64TruncSignedf64     = 0x90,
    i64TruncUnsignedf64   = 0x91,
    f32ConvertSignedi32   = 0x92,
    f32ConvertUnsignedi32 = 0x93,
    f32ConvertSignedi64   = 0x94,
    f32ConvertUnsignedi64 = 0x95,
    f32Demotef64          = 0x96,
    f64ConvertSignedi32   = 0x97,
    f64ConvertUnsignedi32 = 0x98,
    f64ConvertSignedi64   = 0x99,
    f64ConvertUnsignedi64 = 0x9a,
    f64Promotef32         = 0x9b,
    i32Reinterpretf32     = 0x9c,
    i64Reinterpretf64     = 0x9d,
    f32Reinterpreti32     = 0x9f,
    f64Reinterpreti64     = 0xa0,

    // Vm interface
    GcStart               = 0xf1,

    // Blockchain api
    GetBalance            = 0xf2,
    SendCurrency          = 0xf3,
    Mint                  = 0xf4,
    Burn                  = 0xf5,
    CreateContract        = 0xf6,
    CreateCurrency        = 0xf7,
    CreateMintable        = 0xf8,
    CallerAddress         = 0xf9,
    CallCurrency          = 0xfa,
    RandomNumber          = 0xfb,
    CurrentTime           = 0xfc,
    CurrentPrice          = 0xfd,
    PriceAt               = 0xfe,
    Suicide               = 0xff
}

impl Instruction {
    pub fn transitions(&self) -> Vec<Instruction> {
        match *self {
            // TODO: Add transitions for all ops
            Instruction::Halt => {
                // Nothing comes really, after halt
                vec![Instruction::End]
            },
            Instruction::Begin => {
                OPS_LIST.to_vec()
            },
            Instruction::Nop => {
                OPS_LIST.to_vec()
            },
            Instruction::If => {
                COMP_OPS.to_vec()
            },
            Instruction::BreakIf => {
                COMP_OPS.to_vec()
            },
            Instruction::Else => {
                OPS_LIST.to_vec()
            },  
            Instruction::Loop => {
                OPS_LIST.to_vec()
            },
            Instruction::End => {
                OPS_LIST.to_vec()
            },
            Instruction::Suicide => {
                // Not after suicide either, stay safe kids
                vec![Instruction::End]
            },
            _ => unimplemented!()
        }
    }
}

/// List containing opcodes which handle control flow or begin blocks.
pub const CT_FLOW_OPS: &'static [Instruction] = &[
    Instruction::Begin,
    Instruction::Loop,
    Instruction::If,
    Instruction::Else
];

/// List containing all comparison operators.
pub const COMP_OPS: &'static [Instruction] = &[
    Instruction::Eqz            ,
    Instruction::Eq             ,
    Instruction::Ne             ,
    Instruction::LtSigned       ,
    Instruction::LtUnsigned     ,
    Instruction::GtSigned       ,
    Instruction::GtUnsigned     ,
    Instruction::LeSigned       ,
    Instruction::LeUnsigned     ,
    Instruction::GeSigned       ,
    Instruction::GeUnsigned     
];

/// Static array containing all default opcodes. 
/// These do not contain block specific operators,
/// such as `Else`, `Break` or `Break if`.
pub const OPS_LIST: &'static [Instruction] = &[
    Instruction::Halt                  ,
    Instruction::Nop                   ,
    Instruction::Begin                 ,
    Instruction::Loop                  ,
    Instruction::If                    ,
    Instruction::End                   ,
    Instruction::Return                ,
    Instruction::Call                  ,

    // Local stack
    Instruction::PushLocal             ,
    Instruction::PopLocal              ,
    Instruction::PickLocal             ,
    Instruction::PeekLocal             ,

    // Operand stack 
    Instruction::PushOperand           ,
    Instruction::PopOperand            ,
    Instruction::PeekOperand           ,

    // State
    Instruction::GetState              ,
    Instruction::SetState              ,

    // Memory load
    Instruction::i32Load               ,
    Instruction::i64Load               ,
    Instruction::f32Load               ,
    Instruction::f64Load               ,
    Instruction::i32Load8Signed        ,
    Instruction::i32Load8Unsigned      ,
    Instruction::i32Load16Signed       ,
    Instruction::i32Load16Unsigned     ,
    Instruction::i64Load8Signed        ,
    Instruction::i64Load8Unsigned      ,
    Instruction::i64Load16Signed       ,
    Instruction::i64Load16Unsigned     ,
    Instruction::i64Load32Signed       ,
    Instruction::i64Load32Unsigned     ,

    // Memory store 
    Instruction::i32Store              ,
    Instruction::i64Store              ,
    Instruction::f32Store              ,
    Instruction::f64Store              ,
    Instruction::i32Store8             ,
    Instruction::i32Store16            ,
    Instruction::i64Store8             ,
    Instruction::i64Store16            ,
    Instruction::i64Store32            ,

    // Array operations
    Instruction::Fetch                 ,

    // Common operations
    Instruction::Add                   ,
    Instruction::Sub                   ,
    Instruction::Mul                   ,
    Instruction::DivSigned             ,
    Instruction::DivUnsigned           ,
    Instruction::RemSigned             ,
    Instruction::RemUnsigned           ,
    Instruction::Min                   ,
    Instruction::Max                   ,

    // Integer only common operations
    Instruction::And                   ,
    Instruction::Or                    ,
    Instruction::Xor                   ,
    Instruction::Shl                   ,
    Instruction::ShrSigned             ,
    Instruction::ShrUnsigned           ,
    Instruction::Rotl                  ,
    Instruction::Rotr                  ,

    // Float only common operations
    Instruction::Abs                   ,
    Instruction::Neg                   ,
    Instruction::Div                   ,
    Instruction::Ceil                  ,
    Instruction::Floor                 ,
    Instruction::Trunc                 ,
    Instruction::Nearest               ,
    Instruction::CopySign              ,
    Instruction::Sqrt                  ,

    // Comparison operators
    Instruction::Eqz                   ,
    Instruction::Eq                    ,
    Instruction::Ne                    ,
    Instruction::LtSigned              ,
    Instruction::LtUnsigned            ,
    Instruction::GtSigned              ,
    Instruction::GtUnsigned            ,
    Instruction::LeSigned              ,
    Instruction::LeUnsigned            ,
    Instruction::GeSigned              ,
    Instruction::GeUnsigned            ,

    // Constants
    Instruction::i32Const              ,
    Instruction::i64Const              ,
    Instruction::f32Const              ,
    Instruction::f64Const              ,
    Instruction::i32Array2             ,
    Instruction::i32Array4             ,
    Instruction::i32Array8             ,
    Instruction::i32Array16            ,
    Instruction::i32Array32            ,
    Instruction::i32Array64            ,
    Instruction::i32Array128           ,
    Instruction::i32Array256           ,
    Instruction::i64Array2             ,
    Instruction::i64Array4             ,
    Instruction::i64Array8             ,
    Instruction::i64Array16            ,
    Instruction::i64Array32            ,
    Instruction::i64Array64            ,
    Instruction::i64Array128           ,
    Instruction::i64Array256           ,
    Instruction::f32Array2             ,
    Instruction::f32Array4             ,
    Instruction::f32Array8             ,
    Instruction::f32Array16            ,
    Instruction::f32Array32            ,
    Instruction::f32Array64            ,
    Instruction::f32Array128           ,
    Instruction::f32Array256           ,
    Instruction::f64Array2             ,
    Instruction::f64Array4             ,
    Instruction::f64Array8             ,
    Instruction::f64Array16            ,
    Instruction::f64Array32            ,
    Instruction::f64Array64            ,
    Instruction::f64Array128           ,
    Instruction::f64Array256           ,

    // Datatype conversions
    Instruction::i32Wrapi64            ,
    Instruction::i32TruncSignedf32     ,
    Instruction::i32TrunsUnsignedf32   ,
    Instruction::i32TruncSignedf64     ,
    Instruction::i32TruncUnsignedf64   ,
    Instruction::i64ExtendSignedi32    ,
    Instruction::i64ExtendUnsignedi32  ,
    Instruction::i64TruncSignedf32     ,
    Instruction::i64TruncUnsignedf32   ,
    Instruction::i64TruncSignedf64     ,
    Instruction::i64TruncUnsignedf64   ,
    Instruction::f32ConvertSignedi32   ,
    Instruction::f32ConvertUnsignedi32 ,
    Instruction::f32ConvertSignedi64   ,
    Instruction::f32ConvertUnsignedi64 ,
    Instruction::f32Demotef64          ,
    Instruction::f64ConvertSignedi32   ,
    Instruction::f64ConvertUnsignedi32 ,
    Instruction::f64ConvertSignedi64   ,
    Instruction::f64ConvertUnsignedi64 ,
    Instruction::f64Promotef32         ,
    Instruction::i32Reinterpretf32     ,
    Instruction::i64Reinterpretf64     ,
    Instruction::f32Reinterpreti32     ,
    Instruction::f64Reinterpreti64     ,

    // Vm interface
    Instruction::GcStart               ,

    // Blockchain api
    Instruction::GetBalance            ,
    Instruction::SendCurrency          ,
    Instruction::Mint                  ,
    Instruction::Burn                  ,
    Instruction::CreateContract        ,
    Instruction::CreateCurrency        ,
    Instruction::CreateMintable        ,
    Instruction::CallerAddress         ,
    Instruction::CallCurrency          ,
    Instruction::RandomNumber          ,
    Instruction::CurrentTime           ,
    Instruction::CurrentPrice          ,
    Instruction::PriceAt               ,
    Instruction::Suicide               
];