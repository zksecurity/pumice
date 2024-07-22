use ark_ff::BigInt;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use felt::Felt252;
use poseidon::{FieldHasher, Poseidon3};

fn criterion_benchmark(c: &mut Criterion) {
    let left = Felt252::new(BigInt([
        0xdeadbeefdeadbeef,
        0xdeadbeefdeadbeef,
        0xdeadbeefdeadbeef,
        0xdeadbeefdeadbeef,
    ]));

    let right = Felt252::new(BigInt([
        0xcafebabecafebabe,
        0xcafebabecafebabe,
        0xcafebabecafebabe,
        0xcafebabecafebabe,
    ]));

    let elems = [left, right].into_iter().cycle();
    let elems_4 = elems.clone().take(4).collect::<Vec<_>>();
    let elems_8 = elems.clone().take(8).collect::<Vec<_>>();
    let elems_16 = elems.clone().take(16).collect::<Vec<_>>();

    c.bench_function("Poseidon3::pair", |b| {
        b.iter(|| black_box(Poseidon3::pair(left, right)))
    });

    c.bench_function("Poseidon3::hash(|4|)", |b| {
        b.iter(|| black_box(Poseidon3::hash(&elems_4)))
    });

    c.bench_function("Poseidon3::hash(|8|)", |b| {
        b.iter(|| black_box(Poseidon3::hash(&elems_8)))
    });

    c.bench_function("Poseidon3::hash(|16|)", |b| {
        b.iter(|| black_box(Poseidon3::hash(&elems_16)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
