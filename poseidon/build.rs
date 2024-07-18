use std::{env, fs, path::Path};

use ark_ff::{BigInt, Field, PrimeField};

use chumsky::{
    self,
    error::Simple,
    primitive::{choice, empty, end, just},
    text::{self, TextParser},
    Parser,
};

use felt::Felt252;

// parse the round keys
const WIDTH: usize = 3;

#[derive(Debug, Clone)]
enum Options {
    Rate(Number),
    Capacity(Number),
    FullRounds(Number),
    PartialRounds(Number),
    Mds(Vec<Vec<Number>>),
    RoundKeys(Vec<Vec<Number>>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum Sign {
    Plus,
    Minus,
}

#[derive(Debug, Clone)]
struct Number {
    sign: Sign,
    digits: String,
}

impl Number {
    fn i64(&self) -> i64 {
        match self.sign {
            Sign::Plus => self.digits.parse().unwrap(),
            Sign::Minus => -self.digits.parse::<i64>().unwrap(),
        }
    }

    fn usize(&self) -> usize {
        assert_eq!(self.sign, Sign::Plus);
        self.digits.parse().unwrap()
    }

    fn field<F: PrimeField>(&self) -> F {
        assert_eq!(self.sign, Sign::Plus);
        let mut res = F::ZERO;
        for c in self.digits.chars() {
            let digit = match c {
                '0' => F::from(0u64),
                '1' => F::from(1u64),
                '2' => F::from(2u64),
                '3' => F::from(3u64),
                '4' => F::from(4u64),
                '5' => F::from(5u64),
                '6' => F::from(6u64),
                '7' => F::from(7u64),
                '8' => F::from(8u64),
                '9' => F::from(9u64),
                _ => panic!("Invalid digit"),
            };
            res = res * F::from(10u64) + digit;
        }
        res
    }
}

fn parse() -> impl Parser<char, Vec<Options>, Error = Simple<char>> {
    fn opt(c: char) -> impl Parser<char, bool, Error = Simple<char>> + Clone {
        choice((just(c).map(|_| true), empty().map(|_| false)))
    }

    let num = opt('-')
        .then(text::int(10))
        .map(|(neg, digits)| Number {
            sign: if neg { Sign::Minus } else { Sign::Plus },
            digits,
        })
        .padded();

    let row = num.clone().separated_by(just(',').padded()).delimited_by(
        just('[').padded(),
        opt(',').padded().then(just(']')).padded(),
    );

    let mxt = row
        .separated_by(just(',').padded())
        .delimited_by(
            just('[').padded(),
            opt(',').padded().then(just(']')).padded(),
        )
        .padded();

    let eq = just("=").padded();

    let opt = choice((
        // parse the rate
        just("Rate")
            .then(eq)
            .then(num.clone())
            .map(|(_, num)| Options::Rate(num)),
        // parse the capacity
        just("Capacity")
            .then(eq)
            .then(num.clone())
            .map(|(_, num)| Options::Capacity(num)),
        // parse the number of full rounds
        just("FullRounds")
            .then(eq)
            .then(num.clone())
            .map(|(_, num)| Options::FullRounds(num)),
        // parse the number of partial rounds
        just("PartialRounds")
            .then(eq)
            .then(num.clone())
            .map(|(_, num)| Options::PartialRounds(num)),
        // parse the matrix
        just("MDS")
            .then(eq)
            .then(mxt.clone())
            .map(|(_, m)| Options::Mds(m)),
        // parse the round keys list
        just("RoundKeys")
            .then(eq)
            .then(mxt.clone())
            .map(|(_, m)| Options::RoundKeys(m)),
    ));

    opt.padded().repeated().then(end()).map(|(v, _)| v)
}

#[allow(clippy::single_char_add_str)]
fn main() {
    // open poseidon3.txt
    let input = include_str!("poseidon3.txt");

    // parse the input
    let parsed = parse().parse(input).unwrap();

    // extract the options
    let mut rate = None;
    let mut capacity = None;
    let mut full_rounds = None;
    let mut partial_rounds = None;
    let mut mds = None;
    let mut round_keys = None;
    for opt in parsed {
        match opt {
            Options::Rate(n) => {
                assert!(rate.is_none());
                rate = Some(n)
            }
            Options::Capacity(n) => {
                assert!(capacity.is_none());
                capacity = Some(n)
            }
            Options::FullRounds(n) => {
                assert!(full_rounds.is_none());
                full_rounds = Some(n)
            }
            Options::PartialRounds(n) => {
                assert!(partial_rounds.is_none());
                partial_rounds = Some(n)
            }
            Options::Mds(m) => {
                assert!(mds.is_none());
                mds = Some(m)
            }
            Options::RoundKeys(m) => {
                assert!(round_keys.is_none());
                round_keys = Some(m)
            }
        }
    }

    // check that all options are present
    let rate = rate.expect("Rate not found");
    let capacity = capacity.expect("Capacity not found");
    let full_rounds = full_rounds.expect("FullRounds not found");
    let partial_rounds = partial_rounds.expect("PartialRounds not found");
    let mds = mds.expect("MDS not found");
    let round_keys = round_keys.expect("RoundKeys not found");

    // check that the mds matrix is the expected one
    let mds: Vec<Vec<i64>> = mds
        .iter()
        .map(|row| row.iter().map(|n| n.i64()).collect())
        .collect();
    assert_eq!(mds, vec![vec![3, 1, 1], vec![1, -1, 1], vec![1, 1, -2]]);

    let rate = rate.usize();
    let capacity = capacity.usize();
    let rounds_full = full_rounds.usize();
    let rounds_partial = partial_rounds.usize();

    // expected number of round keys
    assert_eq!(rate + capacity, WIDTH);
    assert_eq!(rounds_full + rounds_partial, round_keys.len());
    assert_eq!(rounds_full % 2, 0);

    // parse the round keys
    let mut parsed_keys: Vec<Vec<Felt252>> = vec![];
    for key in round_keys {
        let key: Vec<Felt252> = key.iter().map(|n| n.field()).collect();
        assert_eq!(key.len(), WIDTH);
        parsed_keys.push(key);
    }

    // precompute the compressed round keys
    fn compute_compressed_round_keys(
        rnd_full_first: &[[Felt252; WIDTH]],
        rnd_partial: &[[Felt252; WIDTH]],
        rnd_full_last: &[[Felt252; WIDTH]],
    ) -> Vec<Felt252> {
        // output
        let mut out = Vec::new();

        // full rounds
        for key in rnd_full_first {
            out.push(key[0]);
            out.push(key[1]);
            out.push(key[2]);
        }

        // handle partial rounds
        let mut st = [Felt252::ZERO, Felt252::ZERO, Felt252::ZERO];
        for key in rnd_partial {
            // add round constant
            st[0] += key[0];
            st[1] += key[1];
            st[2] += key[2];

            // add the state to the output
            out.push(st[2]);
            st[2] = Felt252::ZERO;

            // mix state
            // M = (
            //  ( 3, 1, 1),
            //  ( 1,-1, 1),
            //  ( 1, 1, -2)
            // )
            // see:
            // https://github.com/starkware-industries/poseidon/blob/main/poseidon3.txt
            let t0 = st[0] + st[1];
            let t1 = t0 + st[2];
            st[0] = t1 + st[0].double();
            st[1] = t1 - st[1].double();
            st[2] = t0 - st[2].double();
        }

        // add the first of the last full-round keys
        st[0] += rnd_full_last[0][0];
        st[1] += rnd_full_last[0][1];
        st[2] += rnd_full_last[0][2];
        out.push(st[0]);
        out.push(st[1]);
        out.push(st[2]);

        // handle remaining full rounds
        for key in rnd_full_last.iter().skip(1) {
            out.push(key[0]);
            out.push(key[1]);
            out.push(key[2]);
        }

        out
    }

    // split round keys into full and partial rounds
    let keys = parsed_keys
        .iter()
        .cloned()
        .map(|key| {
            let key: [Felt252; WIDTH] = key.try_into().unwrap();
            key
        })
        .collect::<Vec<[Felt252; WIDTH]>>();

    let (first_full, rem) = keys.split_at(rounds_full / 2);
    let (partial, last_full) = rem.split_at(rounds_partial);

    assert_eq!(partial.len(), rounds_partial);
    assert_eq!(last_full.len(), rounds_full / 2);
    assert_eq!(first_full.len(), rounds_full / 2);

    fn fmt_field(field: Felt252) -> String {
        let bn: BigInt<4> = field.into_bigint();
        let vs = bn.0;
        assert_eq!(vs.len(), 4);
        format!(
            "    Felt252::new(BigInt([0x{:016x},0x{:016x},0x{:016x},0x{:016x}]))",
            vs[0], vs[1], vs[2], vs[3]
        )
    }

    // generate the compressed round keys
    let compressed = compute_compressed_round_keys(first_full, partial, last_full);

    let mut output = String::new();

    output.push_str("#[allow(dead_code)]\n");
    output.push_str(format!("pub const RATE: usize = {};\n", rate).as_str());
    output.push_str("\n");

    output.push_str("#[allow(dead_code)]\n");
    output.push_str(format!("pub const CAPACITY: usize = {};\n", capacity).as_str());
    output.push_str("\n");

    output.push_str("#[allow(dead_code)]\n");
    output.push_str(format!("pub const WIDTH: usize = {};\n", WIDTH).as_str());
    output.push_str("\n");

    output.push_str("#[allow(dead_code)]\n");
    output.push_str(format!("pub const ROUNDS_FULL: usize = {};\n", rounds_full).as_str());
    output.push_str("\n");

    output.push_str("#[allow(dead_code)]\n");
    output.push_str(format!("pub const ROUNDS_PARTIAL: usize = {};\n", rounds_partial).as_str());
    output.push_str("\n");

    output.push_str("#[allow(dead_code)]\n");
    output.push_str(
        format!(
            "pub const ROUND_KEYS_COMPRESSED: [Felt252; {}] = [\n",
            compressed.len()
        )
        .as_str(),
    );
    for key in compressed {
        output.push_str(&format!("{},\n", fmt_field(key)));
    }
    output.push_str("];");
    output.push_str("\n");

    // write the output to the file
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("cnst.rs");
    fs::write(&dest_path, output).unwrap();
    println!("cargo::rerun-if-changed=build.rs");
}
