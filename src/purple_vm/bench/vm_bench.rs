//#![feature(test)]

#[macro_use]
extern crate criterion;

#[macro_use]
extern crate bin_tools;

use bitvec::*;
use criterion::Criterion;
use crypto::{Hash, ShortHash};
use patricia_trie::{Trie, TrieDBMut};
use persistence::*;
use purple_vm::*;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("fibonacci 10", |b| {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;
        let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

        let mut block = get_fib_block1(10);
        block.extend_from_slice(&get_fib_block2());

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: None,
            arguments: vec![],
        };

        let module = Module {
            module_hash: Hash::NULL,
            functions: vec![function],
            imports: vec![],
        };

        vm.load(module).unwrap();
        b.iter(|| {
            vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap())
                .unwrap()
        });
    });

    c.bench_function("fibonacci 50", |b| {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;
        let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

        let mut block = get_fib_block1(50);
        block.extend_from_slice(&get_fib_block2());

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: None,
            arguments: vec![],
        };

        let module = Module {
            module_hash: Hash::NULL,
            functions: vec![function],
            imports: vec![],
        };

        vm.load(module).unwrap();
        b.iter(|| {
            vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap())
                .unwrap()
        });
    });

    c.bench_function("fibonacci 100", |b| {
        let mut vm = Vm::new();
        let mut db = test_helpers::init_tempdb();
        let mut root = ShortHash::NULL_RLP;
        let mut trie = TrieDBMut::<DbHasher, Codec>::new(&mut db, &mut root);

        let mut block = get_fib_block1(100);
        block.extend_from_slice(&get_fib_block2());

        let function = Function {
            arity: 0,
            name: "debug_test".to_owned(),
            block: block,
            return_type: None,
            arguments: vec![],
        };

        let module = Module {
            module_hash: Hash::NULL,
            functions: vec![function],
            imports: vec![],
        };

        vm.load(module).unwrap();
        b.iter(|| {
            vm.execute(&mut trie, 0, 0, &[], Gas::from_bytes(b"0.0").unwrap())
                .unwrap()
        });
    });
}

fn get_fib_block1(n: u64) -> Vec<u8> {
    let mut block: Vec<u8> = vec![
        Instruction::Begin.repr(),
        0x00, // 0 Arity
        Instruction::Nop.repr(),
        Instruction::PushOperand.repr(),
        0x04, // 4 Arity
        0x00, // Reference bits
        Instruction::i64Const.repr(),
        Instruction::i64Const.repr(),
        Instruction::i64Const.repr(),
        Instruction::f64Const.repr(),
    ];

    block.extend_from_slice(&encode_be_u64!(n));
    block
}

fn get_fib_block2() -> Vec<u8> {
    let mut bitmask: u8 = 0;
    let mut bitmask2: u8 = 0;
    let mut bitmask3: u8 = 0;

    bitmask.set(0, true);
    bitmask.set(1, true);
    bitmask.set(2, true);

    bitmask2.set(0, true);
    bitmask2.set(1, true);

    bitmask3.set(0, true);

    let block: Vec<u8> = vec![
        0x00, // a = 0
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // b = 1
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00, // sum = 0
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        Instruction::i64Store.repr(), // Store sum at 0x00, 0x03
        0x00,
        0x03,
        Instruction::i64Store.repr(), // Store b at 0x00, 0x02
        0x00,
        0x02,
        Instruction::i64Store.repr(), // Store a at 0x00, 0x01
        0x00,
        0x01,
        Instruction::i64Store.repr(), // Store n at 0x00, 0x00
        0x00,
        0x00,
        Instruction::Loop.repr(),
        0x00,
        Instruction::PushOperand.repr(), // Push n to operand stack and check if n > 1
        0x02,
        bitmask3,
        Instruction::i64Const.repr(),
        Instruction::i64Const.repr(),
        Instruction::i64Load.repr(),
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        Instruction::BreakIf.repr(), // Break loop if n is less than 2
        Instruction::LtSigned.repr(),
        Instruction::PopOperand.repr(),
        Instruction::PushLocal.repr(), // Push n, b and a to locals stack
        0x03,
        bitmask,
        Instruction::i64Const.repr(),
        Instruction::i64Const.repr(),
        Instruction::i64Const.repr(),
        Instruction::PopOperand.repr(),
        Instruction::i64Load.repr(),
        0x00,
        0x02,
        Instruction::i64Load.repr(),
        0x00,
        0x01,
        Instruction::PickLocal.repr(), // Copy b to the top of the stack
        0x00,
        0x02,
        Instruction::PushOperand.repr(), // Push a and copy of b on the operand stack
        0x02,
        bitmask2,
        Instruction::i64Const.repr(),
        Instruction::i64Const.repr(),
        Instruction::PopLocal.repr(),
        Instruction::PopLocal.repr(),
        Instruction::Add.repr(),         // sum = a + b
        Instruction::PickOperand.repr(), // Dupe sum on the operand stack
        0x00,
        0x00,
        Instruction::i64Store.repr(), // Store new sum at 0x00, 0x03
        0x00,
        0x03,
        Instruction::PushOperand.repr(), // Push b on the operand stack
        0x01,
        bitmask3,
        Instruction::i64Const.repr(),
        Instruction::PopLocal.repr(),
        Instruction::i64Store.repr(), // Store b as new a at 0x00, 0x01
        0x00,
        0x01,
        Instruction::i64Store.repr(), // Store sum as new b at 0x00, 0x02
        0x00,
        0x02,
        Instruction::PushOperand.repr(), // Push b on the operand stack and subtract by 1
        0x02,
        bitmask3,
        Instruction::i64Const.repr(),
        Instruction::i64Const.repr(),
        Instruction::PopLocal.repr(),
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        Instruction::Sub.repr(),
        Instruction::i64Store.repr(), // Store new n at 0x00, 0x00
        0x00,
        0x00,
        Instruction::End.repr(),
        Instruction::Nop.repr(),
        Instruction::End.repr(),
    ];

    block
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
