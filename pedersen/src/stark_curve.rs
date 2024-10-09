// parameters copied from :
// https://docs.starknet.io/architecture-and-concepts/cryptography/stark-curve/
// https://github.com/starkware-libs/stone-prover/blob/main/src/starkware/algebra/elliptic_curve/elliptic_curve_constants.h
use ark_ec::{models::CurveConfig, short_weierstrass, short_weierstrass::SWCurveConfig};
use ark_ff::{
    fields::{MontBackend, MontConfig},
    Field, Fp256, MontFp,
};
use felt::Felt252;

#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105526743751716087489154079457884512865583"]
#[generator = "3"]
pub struct ScalarFieldConfig;
pub type Fr = Fp256<MontBackend<ScalarFieldConfig, 4>>;

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct StarkCurveConfig;

impl CurveConfig for StarkCurveConfig {
    type BaseField = Felt252;
    type ScalarField = Fr;

    // COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    // COFACTOR_INV = 1
    const COFACTOR_INV: Fr = Fr::ONE;
}

pub type Affine = short_weierstrass::Affine<StarkCurveConfig>;
pub type Projective = short_weierstrass::Projective<StarkCurveConfig>;

impl SWCurveConfig for StarkCurveConfig {
    // COEFF_A = 1
    const COEFF_A: Felt252 = Felt252::ONE;

    // COEFF_B = 3141592653589793238462643383279502884197169399375105820974944592307816406665
    const COEFF_B: Felt252 =
        MontFp!("3141592653589793238462643383279502884197169399375105820974944592307816406665");

    // AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const GENERATOR: Affine = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

// G_GENERATOR_X = 874739451078007766457464989774322083649278607533249481151382481072868806602
pub const G_GENERATOR_X: Felt252 =
    MontFp!("874739451078007766457464989774322083649278607533249481151382481072868806602");

// G_GENERATOR_Y = 152666792071518830868575557812948353041420400780739481342941381225525861407
pub const G_GENERATOR_Y: Felt252 =
    MontFp!("152666792071518830868575557812948353041420400780739481342941381225525861407");
