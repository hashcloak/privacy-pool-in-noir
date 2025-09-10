contract;

use std::hash::Hash;
use std::hash::keccak256;
use std::array_conversions::u256::*;
use std::bytes_conversions::u256::*;
use std::bytes::Bytes;

const N: u256 = 32768;
const LOG_N: u256 = 15;
const NUMBER_OF_PUBLIC_INPUTS: u64 = 20;


pub fn load_vk() -> VerificationKey {
    VerificationKey {
        circuit_size: 0x8000u256,
        log_circuit_size: 0xfu256,
        public_inputs_size: 0x14u256,
        qm: G1Point {
            x: 0x03bd8355a55341c797b8a374f5ee198e75b2a156e9b970bb067d2570a40a0398u256,
            y: 0x01a2245f3d7e1546ee10095aa147b6d0485e3dee45e2d18bdb5e6803cf1c69a1u256,
        },
        qc: G1Point {
            x: 0x15137e5ff3632a94c6f50ec95815b82b68227da81a4903372175d69248e59d5cu256,
            y: 0x14686961a45e0c203c506637d006bb3884bebabf045ad3dcb10e30994d99b92du256,
        },
        ql: G1Point {
            x: 0x24b001cc33620a5062233e350c43d2bceee019949cc6d0ed69fa832fd1f82cbbu256,
            y: 0x2718a27457fb4e8801c0b2a3bb27aad907037cab34fd1e48f3c34342dc76f587u256,
        },
        qr: G1Point {
            x: 0x2ba5ba9ff29da7132b7925b21ab1099e7884da66853ee77eaae46c0224593227u256,
            y: 0x0c76890abba9ac45cefab8fbbd6cb4b479127f2e836cb1096e529b761713e8b2u256,
        },
        qo: G1Point {
            x: 0x302b566e2e27a0cdac08868d2d58877b164a68ba9a3c395ead3d9d35ba1c9c5eu256,
            y: 0x17819f470c021e658622e7216f194cd689b4012c542bd6ada0fa9260ccd3a8b6u256,
        },
        q4: G1Point {
            x: 0x1a495e36de1fc656ac2001e3159a85414a0d065832a62113d96799034a513315u256,
            y: 0x304048bb6f83ce466df4c60811511cf8c9813ca318b627fc7b28a01d9a42a373u256,
        },
        q_lookup: G1Point {
            x: 0x038147f7985ab2a8d179a7a764ee622afc5cac5dabeb8f74a2f89ad33f068fe4u256,
            y: 0x24095afc77887b20f8293c4a2602c55c7f68b34721dbdaa9d8f2cfc9f432da95u256,
        },
        q_arith: G1Point {
            x: 0x06a3a2318ea7c27a14e06d3df72022e1e18f88e9096bac939dfe4c83350b1099u256,
            y: 0x00007394bb4d7f10a17e01e3d6ab94bef815fb9f20bc17e9433f6ddba96de82eu256,
        },
        q_delta_range: G1Point {
            x: 0x1ca4d86f0d7858358036d917fe9f0c61e2bf3b87b38615bb1dbb76ce5240b933u256,
            y: 0x28d90f01092ae2ad1e078adc5938d5e5f5fb5a5bfe3ace1111d471044a4f5617u256,
        },
        q_elliptic: G1Point {
            x: 0x0fd8733db81994ba4d4232b0e8503d276d07e3382a97f4d3d6a6b0b583721d2fu256,
            y: 0x2c6d727d907774304a7b4c7c91f6ee1c4982acdbe0ce451691e3c69c2bbdf5dcu256,
        },
        q_aux: G1Point {
            x: 0x2d1d26ed7490876532fbbe5789c16aa8485f3cb0b1a1560639071e9cde939e9au256,
            y: 0x29bc4468368045f2c78adcfcb60ee491dc395fd6375107c6f4675d56fecec73du256,
        },
        q_poseidon2_external: G1Point {
            x: 0x304dcf6cec51b706610e2663a8e1ad86b02862f6c42ea86250ea59868108a1c9u256,
            y: 0x10b1e0cd80f29c908ece3dab916058ec2f56a416075546cb5b31313cc71f48f2u256,
        },
        q_poseidon2_internal: G1Point {
            x: 0x033359a90c86e0522939bb30e6cb63509ca3ac60828c1690807a672c60555f41u256,
            y: 0x0de6e852fab33fcc39317de669b5c858a2d97cf87249f9c4150c38ddb1d0e579u256,
        },
        s1: G1Point {
            x: 0x20cf4e372496eac6b2b02f88b5208c00973b50ab69e810b536b3457939f8c127u256,
            y: 0x20190da1c1a3943098dde18a4597ed018bdc230940260e82f5a840b821450b29u256,
        },
        s2: G1Point {
            x: 0x2774e34442f01b292417836233d2acbf0dd9189e554f523eeb7351b5497536c6u256,
            y: 0x0fe04dc173348b3cf3c3018220a3f85e5c014d52e2b6c75fe48f2873f8a70633u256,
        },
        s3: G1Point {
            x: 0x10c7800efe37eb53443743d697c6afacb117927a5755b0c97e7d673fbbeb20a7u256,
            y: 0x042d9128643f04113ff1aea3d76e84853ba869b102287d4245fe3ce88fdef37eu256,
        },
        s4: G1Point {
            x: 0x160f3943e9e54ee9876d0c7025b4eabbd637cc3c421c3f3f91b67b01805e4991u256,
            y: 0x06fa21ac478d565ca102fa817931d15bad96e2fd60a1541ebc7203fc3565fed0u256,
        },
        t1: G1Point {
            x: 0x0cb15289361c0a0e1b78f25efb7e6f3cee056cd8653f11fe91bec67f9a1ba501u256,
            y: 0x29664df9e7f07b4aec2f396f6cde12443f54f12a87c2cf5182f3620fc1944c6du256,
        },
        t2: G1Point {
            x: 0x070b433d46367e191b9bf40eef28b673875103abf917a76019cf7bba4da77621u256,
            y: 0x26eccd7100479fc88688e129589197a0af4c7b9ef86fe2480692f5f6dc52534au256,
        },
        t3: G1Point {
            x: 0x1d62dc541680650e594af57d0903209fb1952dd9aeab56e182d68b662852e36au256,
            y: 0x150131f285f1648db0d2d85128255b8dff03113bc84bd8a1582702c3a51cc8fdu256,
        },
        t4: G1Point {
            x: 0x0082e0b52e8df94612b14bc2afb9f76f575a60d3c9d50fc277988d94997a5ddbu256,
            y: 0x26a696f75adf15d5934d9edad81c9bfe073ff12f2bad78b10ae4a1629516a075u256,
        },
        id1: G1Point {
            x: 0x2f482e20dfadb0c600041f44703d2e232b2303dbef67114f1608b8775e4a8b2cu256,
            y: 0x101ea6046b1d6758b3719a3fe6ebe0e652dbb33242b9d36afa9d5f3ab81e458bu256,
        },
        id2: G1Point {
            x: 0x2b169c7d6c8a8766515a84eedde577d87a79008f4a1a9a99b292e225159d720du256,
            y: 0x07bc40d00c40438d0d603f74f5f1685070788af0a9a47325c216bddcfe6edec4u256,
        },
        id3: G1Point {
            x: 0x2375c7b4b673e1472540c0662cfdb83a523da1804a63e3dd5bf9f4500e523da7u256,
            y: 0x02f5592cf077e535e0da4a8a2c4c1f6475060d653dc54993199ed7699f0d9a1du256,
        },
        id4: G1Point {
            x: 0x0809e3b1ce584bc668d72f84d4204939f347c17f0236e8c4c1c84a3b03e6b7a7u256,
            y: 0x1224d290859033f8dbc6bd8ec82237b3530d9aa2dd2c6a326157683930d2a04cu256,
        },
        lagrange_first: G1Point {
            x: 0x0000000000000000000000000000000000000000000000000000000000000001u256,
            y: 0x0000000000000000000000000000000000000000000000000000000000000002u256,
        },
        lagrange_last: G1Point {
            x: 0x2abb0d5d782d28ee60469f0b3aeda621f169588f60400c8176652e4016be1459u256,
            y: 0x2384a18c2da6a998d117644d3f5ed241caa1d7892517be0837cee6cc81550721u256,
        },
    }
}

#[error_type]
enum VerifierErrors {
    #[error(m = "Sumcheck failed.")]
    SumcheckFailed: (),
    #[error(m = "Shplemini failed.")]
    ShpleminiFailed: (),
    #[error(m = "Public inputs length wrong.")]
    PublicInputsLengthWrong: (),
}

const ZERO: u256 = 0;

// ORIGINAL FROM SOLIDITY 21888242871839275222246405745257275088548364400416034343698204186575808495617
// Prime field order, F_r (used for all modular arithmetic)
const MODULUS: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001u256;

// EC group order, F_q
const Q: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47u256;

// Minus one in the field
const MINUS_ONE: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000u256; // = MODULUS - 1

const CONST_PROOF_SIZE_LOG_N: u64 = 28;
const CONST_PROOF_SIZE_LOG_N_MINUS_1: u64 = 27;
const NUMBER_OF_SUBRELATIONS: u64 = 26;
const BATCHED_RELATION_PARTIAL_LENGTH: u64 = 8;
const NUMBER_OF_ENTITIES: u64 = 40;
const NUMBER_UNSHIFTED: u64 = 35;
// Unused, but keeping for consistency with Solidity
const NUMBER_TO_BE_SHIFTED: u64 = 5;
const PAIRING_POINTS_SIZE: u64 = 16;
const NUMBER_OF_ALPHAS: u64 = 25;

// Functions hardcoded mod MODULUS
impl u256 {
  fn addmod(self, other: u256) -> u256 {
      let mut res: u256 = 0;
      asm (rA: res, rB: self, rC: other, rD: MODULUS) {
      wqam rA rB rC rD;
      };
      res
  }

  fn mulmod(self, other: u256) -> u256 {
      let mut res: u256 = 0;
      asm (rA: res, rB: self, rC: other, rD: MODULUS) {
      wqmm rA rB rC rD;
      }
      res
  }

  fn submod(self, other: u256) -> u256 {
      let mut res: u256 = MODULUS - other;
      asm (rA: res, rB: self, rD: MODULUS) {
      wqam rA rB rA rD;
      }
      res
  }
}

// Computes the inverse using the extended euclidean algorithm
fn inverse(a: u256) -> u256 {
    let mut t = 0;
    let mut newt = 1;
    let mut r = MODULUS;
    let mut newr = a;
    let mut quotient = 0;
    let mut aux = 0;
    while newr != 0 {
      quotient = r / newr;
      // aux = t - quotient*newt
      let mut qt = 0;
      asm (rA: qt, rB: quotient, rC: newt, rD: MODULUS){
        wqmm rA rB rC rD;
      }
      qt = MODULUS - qt;
      asm (rA: aux, rB: t, rC: qt, rD: MODULUS){
        wqam rA rB rC rD;
      }
      t = newt;
      newt = aux;
      // aux = r - quotient*newr
      let mut qr = 0;
      asm (rA: qr, rB: quotient, rC: newr, rD: MODULUS){
        wqmm rA rB rC rD;
      }
      qr = MODULUS - qr;
      asm (rA: aux, rB: r, rC: qr, rD: MODULUS){
        wqam rA rB rC rD;
      }
      r = newr;
      newr = aux;
    };
    t
}

// G1
pub struct G1Point {
    pub x: u256,
    pub y: u256,
}

// G1ProofPoint
pub struct G1ProofPoint {
    pub x: [u256;2],
    pub y: [u256;2],
}

// [1]_2
const G2x1: u256 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6edu256;
const G2x2: u256 = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2u256;
const G2y1: u256 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daau256;
const G2y2: u256 = 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975bu256;

// Values from VK
const X2x1: u256 = 0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0u256;
const X2x2: u256 = 0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1u256;
const X2y1: u256 = 0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55u256;
const X2y2: u256 = 0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4u256;


pub fn convert_proof_point(input: G1ProofPoint) -> G1Point {
    G1Point {
        x: input.x[0] | (input.x[1] << 136),
        y: input.y[0] | (input.y[1] << 136),
    }
}

impl G1Point {

    pub fn point_add(self, other: G1Point) -> Self {
        let mut input: [u256; 4] = [0; 4];
        let mut output: [u256; 2] = [0; 2];

        // prepare input
        input[0] = self.x;
        input[1] = self.y;
        input[2] = other.x;
        input[3] = other.y;

        // ecc addition opcode
        asm(rA: output, rB: 0, rC: 0, rD: input) {
            ecop rA rB rC rD;
        }

        G1Point{
            x: output[0],
            y: output[1],
        }
    }

    pub fn u256_mul(self, s: u256) -> Self {
        let mut input: [u256; 3] = [0; 3];
        let mut output: [u256; 2] = [0; 2];

        // prepare input
        input[0] = self.x;
        input[1] = self.y;
        input[2] = s;

        // ecc multiplication opcode
        asm(rA: output, rB: 0, rC: 1, rD: input) {
            ecop rA rB rC rD;
        }

        G1Point{
            x: output[0],
            y: output[1],
        }
    }
}

// 70 = N = NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 2
pub fn batch_mul(points: [G1Point; 70], scalars: [u256; 70]) -> G1Point {
    let mut acc = points[0].u256_mul(scalars[0]);
    let mut i = 1;
    while i < 70 {
        let tmp = points[i].u256_mul(scalars[i]);
        acc = acc.point_add(tmp);
        i += 1;
    }
    acc
}

pub struct VerificationKey {
    // Misc Params
    pub circuit_size: u256,
    pub log_circuit_size: u256,
    pub public_inputs_size: u256,

    // Selectors
    pub qm: G1Point,
    pub qc: G1Point,
    pub ql: G1Point,
    pub qr: G1Point,
    pub qo: G1Point,
    pub q4: G1Point,
    pub q_lookup: G1Point,
    pub q_arith: G1Point,
    pub q_delta_range: G1Point,
    pub q_aux: G1Point,
    pub q_elliptic: G1Point,
    pub q_poseidon2_external: G1Point,
    pub q_poseidon2_internal: G1Point,

    // Copy constraints
    pub s1: G1Point,
    pub s2: G1Point,
    pub s3: G1Point,
    pub s4: G1Point,

    // Copy identity
    pub id1: G1Point,
    pub id2: G1Point,
    pub id3: G1Point,
    pub id4: G1Point,

    // Precomputed lookup table
    pub t1: G1Point,
    pub t2: G1Point,
    pub t3: G1Point,
    pub t4: G1Point,

    // Fixed first and last Lagrange selectors
    pub lagrange_first: G1Point,
    pub lagrange_last: G1Point,
}

pub struct RelationParameters {
    // Fiat-Shamir challenges
    pub eta: u256,
    pub eta_two: u256,
    pub eta_three: u256,
    pub beta: u256,
    pub gamma: u256,
    // derived
    pub public_inputs_delta: u256,
}

pub struct Proof {
    // Pairing point object (values in Fr)
    // PAIRING_POINTS_SIZE
    pub pairing_point_object: [u256; 16],

    // Free wires
    pub w1: G1ProofPoint,
    pub w2: G1ProofPoint,
    pub w3: G1ProofPoint,
    pub w4: G1ProofPoint,

    // Lookup helpers - Permutations
    pub z_perm: G1ProofPoint,

    // Lookup helpers - Lookup-specific
    pub lookup_read_counts: G1ProofPoint,
    pub lookup_read_tags: G1ProofPoint,
    pub lookup_inverses: G1ProofPoint,

    // Sumcheck
    // pub sumcheck_univariates: [[u256; BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
    pub sumcheck_univariates: [[u256; 8]; 28],
    // NUMBER_OF_ENTITIES
    pub sumcheck_evaluations: [u256; 40],

    // Shplemini (Gemini commitments + Shplonk opening proof)
    // CONST_PROOF_SIZE_LOG_N_MINUS_1
    pub gemini_fold_comms: [G1ProofPoint; 27],
    // CONST_PROOF_SIZE_LOG_N
    pub gemini_a_evaluations: [u256; 28],
    pub shplonk_q: G1ProofPoint,
    pub kzg_quotient: G1ProofPoint,
}

// Replacement for enum WIRES in Solidity
// (this is used for indexing into sumcheck_evaluations of the Proof struct)
pub const WIRE_Q_M: u64                  = 0;
pub const WIRE_Q_C: u64                  = 1;
pub const WIRE_Q_L: u64                  = 2;
pub const WIRE_Q_R: u64                  = 3;
pub const WIRE_Q_O: u64                  = 4;
pub const WIRE_Q_4: u64                  = 5;
pub const WIRE_Q_LOOKUP: u64             = 6;
pub const WIRE_Q_ARITH: u64              = 7;
pub const WIRE_Q_RANGE: u64              = 8;
pub const WIRE_Q_ELLIPTIC: u64           = 9;
pub const WIRE_Q_AUX: u64                = 10;
pub const WIRE_Q_POSEIDON2_EXTERNAL: u64 = 11;
pub const WIRE_Q_POSEIDON2_INTERNAL: u64 = 12;
pub const WIRE_SIGMA_1: u64              = 13;
pub const WIRE_SIGMA_2: u64              = 14;
pub const WIRE_SIGMA_3: u64              = 15;
pub const WIRE_SIGMA_4: u64              = 16;
pub const WIRE_ID_1: u64                 = 17;
pub const WIRE_ID_2: u64                 = 18;
pub const WIRE_ID_3: u64                 = 19;
pub const WIRE_ID_4: u64                 = 20;
pub const WIRE_TABLE_1: u64              = 21;
pub const WIRE_TABLE_2: u64              = 22;
pub const WIRE_TABLE_3: u64              = 23;
pub const WIRE_TABLE_4: u64              = 24;
pub const WIRE_LAGRANGE_FIRST: u64       = 25;
pub const WIRE_LAGRANGE_LAST: u64        = 26;
pub const WIRE_W_L: u64                  = 27;
pub const WIRE_W_R: u64                  = 28;
pub const WIRE_W_O: u64                  = 29;
pub const WIRE_W_4: u64                  = 30;
pub const WIRE_Z_PERM: u64               = 31;
pub const WIRE_LOOKUP_INVERSES: u64      = 32;
pub const WIRE_LOOKUP_READ_COUNTS: u64   = 33;
pub const WIRE_LOOKUP_READ_TAGS: u64     = 34;
pub const WIRE_W_L_SHIFT: u64            = 35;
pub const WIRE_W_R_SHIFT: u64            = 36;
pub const WIRE_W_O_SHIFT: u64            = 37;
pub const WIRE_W_4_SHIFT: u64            = 38;
pub const WIRE_Z_PERM_SHIFT: u64         = 39;

// Transcript library to generate fiat shamir challenges
pub struct Transcript {
    pub relation_parameters: RelationParameters,
    // NUMBER_OF_ALPHAS = 25
    pub alphas: [u256; 25],
    // CONST_PROOF_SIZE_LOG_N = 28
    pub gate_challenges: [u256; 28],
    // CONST_PROOF_SIZE_LOG_N = 28
    pub sumcheck_u_challenges: [u256; 28],
    pub rho: u256,
    pub gemini_r: u256,
    pub shplonk_nu: u256,
    pub shplonk_z: u256,
}

pub fn generate_transcript(proof: Proof, public_inputs: [u256;4], circuit_size: u256, pub_inputs_offset: u256)  -> Transcript {
    let (relation_parameters, previous_challenge0): (RelationParameters, u256) = generate_relation_parameters_challenges(proof, public_inputs, circuit_size, pub_inputs_offset);

    let (alphas, previous_challenge1): ([u256; 25], u256)  = generate_alpha_challenges(proof, previous_challenge0);

    let (gate_challenges, previous_challenge2): ([u256; 28], u256) = generate_gate_challenges(previous_challenge1);

    let (sumcheck_u_challenges, previous_challenge3): ([u256; 28], u256) = generate_sumcheck_challenges(proof, previous_challenge2);

    let (rho_challenge_elements, rho, previous_challenge4): ([u256;41], u256, u256) = generate_rho_challenge(proof, previous_challenge3);

    let (g_R, gemini_r, previous_challenge5): ([u256;109], u256, u256) = generate_gemini_R_challenge(proof, previous_challenge4);

    let (shplonk_nu_challenge_elements, shplonk_nu, previous_challenge6): ([u256; 29], u256, u256) = generate_shplonk_nu_challenge(proof, previous_challenge5);

    let (shplonk_Z_challenge, shplonk_Z, previous_challenge7): ([u256;5], u256, u256) = generate_shplonk_z_challenge(proof, previous_challenge6);

    Transcript {
        relation_parameters: relation_parameters,
        alphas: alphas,
        gate_challenges: gate_challenges,
        sumcheck_u_challenges: sumcheck_u_challenges,
        rho: rho,
        gemini_r: gemini_r,
        shplonk_nu: shplonk_nu,
        shplonk_z: shplonk_Z
    }
}

// Takes a field element and splits it into high and low
// (the result will be in field as well)
pub fn split_challenge(challenge: u256) -> (u256, u256) {
    let lo_mask: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu256;

    let lo: u256 = challenge & lo_mask;
    let hi: u256 = challenge >> 128;

    (lo, hi)
}

pub fn generate_relation_parameters_challenges(
  proof: Proof,
  public_inputs: [u256;4],
  circuit_size: u256,
  pub_inputs_offset: u256,
) -> (RelationParameters, u256) {
  let eta_res = generate_eta_challenge(proof, public_inputs, circuit_size, pub_inputs_offset);
  let previous_challenge = eta_res[3];
  let beta_gamma_res = generate_beta_and_gamma_challenges(proof, previous_challenge);

  (RelationParameters {
    eta: eta_res[0],
    eta_two: eta_res[1],
    eta_three: eta_res[2],
    beta: beta_gamma_res[0],
    gamma: beta_gamma_res[1],
    public_inputs_delta: 0,
  }, beta_gamma_res[2])
}

// uses 3 + NUMBER_OF_PUBLIC_INPUTS + 12
const ROUND0_LEN: u64 = 32;
pub fn generate_eta_challenge(
    proof: Proof,
    public_inputs: [u256; 4],
    circuit_size: u256,
    pub_inputs_offset: u256,
) -> [u256; 4] {
    let mut transcript = Bytes::new();

    // Append meta
    transcript.append(circuit_size.to_be_bytes());
    transcript.append(NUMBER_OF_PUBLIC_INPUTS.as_u256().to_be_bytes());
    transcript.append(pub_inputs_offset.to_be_bytes());

    // Public inputs
    let mut i = 0;
    while i < NUMBER_OF_PUBLIC_INPUTS - PAIRING_POINTS_SIZE {
        transcript.append(public_inputs[i].to_be_bytes());
        i += 1;
    }

    // Pairing point objects
    let mut j = 0;
    while j < PAIRING_POINTS_SIZE {
        transcript.append(proof.pairing_point_object[j].to_be_bytes());
        j += 1;
    }

    // Wires
    transcript.append(proof.w1.x[0].to_be_bytes());
    transcript.append(proof.w1.x[1].to_be_bytes());
    transcript.append(proof.w1.y[0].to_be_bytes());
    transcript.append(proof.w1.y[1].to_be_bytes());
    transcript.append(proof.w2.x[0].to_be_bytes());
    transcript.append(proof.w2.x[1].to_be_bytes());
    transcript.append(proof.w2.y[0].to_be_bytes());
    transcript.append(proof.w2.y[1].to_be_bytes());
    transcript.append(proof.w3.x[0].to_be_bytes());
    transcript.append(proof.w3.x[1].to_be_bytes());
    transcript.append(proof.w3.y[0].to_be_bytes());
    transcript.append(proof.w3.y[1].to_be_bytes());

    // Hash round 0 = previous challenge mod MODULUS
    let hash_0 = keccak256(transcript);
    let mut hash_0_field: u256 = 0;
    asm (rA: hash_0_field, rB: hash_0, rC: ZERO, rD: MODULUS) {
        wqam rA rB rC rD;
    };
    let (eta, eta_two) = split_challenge(hash_0_field);

    // Next challenge input: just the previous challenge
    let hash_1 = keccak256(hash_0_field);
    let mut hash_1_field: u256 = 0;

    asm (rA: hash_1_field, rB: hash_1, rC: ZERO, rD: MODULUS) {
        wqam rA rB rC rD;
    };
    let (eta_three, _) = split_challenge(hash_1_field);

    [eta, eta_two, eta_three, hash_1_field]
}

pub fn generate_beta_and_gamma_challenges(
    proof: Proof,
    previous_challenge: u256,
) -> [u256; 3] {
    let mut transcript = Bytes::new();

    // 0: the previous challenge in bytes
    transcript.append(previous_challenge.to_be_bytes());

    // 1–4: lookupReadCounts.x0, x1, y0, y1
    transcript.append(proof.lookup_read_counts.x[0].to_be_bytes());
    transcript.append(proof.lookup_read_counts.x[1].to_be_bytes());
    transcript.append(proof.lookup_read_counts.y[0].to_be_bytes());
    transcript.append(proof.lookup_read_counts.y[1].to_be_bytes());

    // 5–8: lookupReadTags.x0, x1, y0, y1
    transcript.append(proof.lookup_read_tags.x[0].to_be_bytes());
    transcript.append(proof.lookup_read_tags.x[1].to_be_bytes());
    transcript.append(proof.lookup_read_tags.y[0].to_be_bytes());
    transcript.append(proof.lookup_read_tags.y[1].to_be_bytes());

    // 9–12: w4.x0, x1, y0, y1
    transcript.append(proof.w4.x[0].to_be_bytes());
    transcript.append(proof.w4.x[1].to_be_bytes());
    transcript.append(proof.w4.y[0].to_be_bytes());
    transcript.append(proof.w4.y[1].to_be_bytes());

    // hash and reduce into field
    let next_previous = keccak256(transcript);

    let mut next_previous_field: u256 = 0;
    asm (rA: next_previous_field, rB: next_previous, rC: ZERO, rD: MODULUS) {
        wqam rA rB rC rD;
    };

    // split out beta & gamma
    let (beta, gamma) = split_challenge(next_previous_field);

    [beta, gamma, next_previous_field]
}

pub fn generate_alpha_challenges(
  proof: Proof,
  previous_challenge: u256,
) -> ([u256; 25], u256) { // NUMBER_OF_ALPHAS = 25

    let mut transcript = Bytes::new();
    transcript.append(previous_challenge.to_be_bytes());
    transcript.append(proof.lookup_inverses.x[0].to_be_bytes());
    transcript.append(proof.lookup_inverses.x[1].to_be_bytes());
    transcript.append(proof.lookup_inverses.y[0].to_be_bytes());
    transcript.append(proof.lookup_inverses.y[1].to_be_bytes());

    transcript.append(proof.z_perm.x[0].to_be_bytes());
    transcript.append(proof.z_perm.x[1].to_be_bytes());
    transcript.append(proof.z_perm.y[0].to_be_bytes());
    transcript.append(proof.z_perm.y[1].to_be_bytes());

    // hash and reduce into field
    let mut next_previous = keccak256(transcript);

    let mut next_previous_field: u256 = 0;
    asm (rA: next_previous_field, rB: next_previous, rC: ZERO, rD: MODULUS) {
        wqam rA rB rC rD;
    };

    // split out in alphas
    let (alpha0, alpha1) = split_challenge(next_previous_field);
    let mut alphas: [u256; 25] = [0; 25];
    alphas[0] = alpha0;
    alphas[1] = alpha1;
    let mut i = 1;
    while i < NUMBER_OF_ALPHAS/2 {
        next_previous = keccak256(next_previous_field.to_be_bytes());
        asm (rA: next_previous_field, rB: next_previous, rC: ZERO, rD: MODULUS) {
            wqam rA rB rC rD;
        };
        let (alpha_next_0, alpha_next_1) = split_challenge(next_previous_field);

        alphas[2*i] = alpha_next_0;
        alphas[2*i+1] = alpha_next_1;
        i += 1;
    }

    if (((NUMBER_OF_ALPHAS & 1) == 1) && NUMBER_OF_ALPHAS > 2) {
        next_previous = keccak256(next_previous_field.to_be_bytes());
        asm (rA: next_previous_field, rB: next_previous, rC: ZERO, rD: MODULUS) {
            wqam rA rB rC rD;
        };
        let (alpha_next_0, unused) = split_challenge(next_previous_field);
        alphas[NUMBER_OF_ALPHAS-1] = alpha_next_0;
    }

    (alphas, next_previous_field)
}

// CONST_PROOF_SIZE_LOG_N = 28
pub fn generate_gate_challenges(previous_challenge: u256) -> ([u256; 28], u256) {
    let mut i = 0;
    let mut temp_previous_challenge_field: u256 = previous_challenge;
    let mut gate_challenges: [u256; 28] = [0u256;28];
    while i < CONST_PROOF_SIZE_LOG_N {
      let hash = keccak256(temp_previous_challenge_field.to_be_bytes());
      asm (rA: temp_previous_challenge_field, rB: hash, rC: ZERO, rD: MODULUS) {
          wqam rA rB rC rD;
      };
      let (gate_challenge, unused) = split_challenge(temp_previous_challenge_field);
      gate_challenges[i] = gate_challenge;
      i += 1;
    }
    (gate_challenges, temp_previous_challenge_field)
}

// CONST_PROOF_SIZE_LOG_N = 28
pub fn generate_sumcheck_challenges(proof: Proof, prev_challenge: u256) -> ([u256; 28], u256) {
    let mut i = 0;
    let mut prev_challenge_field = prev_challenge;
    let mut sumcheck_challenges: [u256; 28] = [0;28];
    while i < CONST_PROOF_SIZE_LOG_N {
      let mut transcript = Bytes::new();
      transcript.append(prev_challenge_field.to_be_bytes());
      let mut j = 0;
      while j < BATCHED_RELATION_PARTIAL_LENGTH {
          transcript.append(proof.sumcheck_univariates[i][j].to_be_bytes());
          j += 1;
      }
      let hash = keccak256(transcript);
      asm (rA: prev_challenge_field, rB: hash, rC: ZERO, rD: MODULUS) {
          wqam rA rB rC rD;
      };
      let (sumcheck_challenge_i, unused) = split_challenge(prev_challenge_field);
      sumcheck_challenges[i] = sumcheck_challenge_i;
      i += 1;
    }
    (sumcheck_challenges, prev_challenge_field)
}

// NUMBER_OF_ENTITIES = 40, length of array is +1
pub fn generate_rho_challenge(proof: Proof, next_previous_challenge: u256) -> ([u256;41], u256, u256) {
    let mut rho_challenge_elements: [u256; 41] = [0u256;41];
    let mut transcript = Bytes::new();
    rho_challenge_elements[0] = next_previous_challenge;
    transcript.append(next_previous_challenge.to_be_bytes());
    let mut i = 0;
    while i < NUMBER_OF_ENTITIES {
        rho_challenge_elements[i+1] = proof.sumcheck_evaluations[i];
        transcript.append(proof.sumcheck_evaluations[i].to_be_bytes());
        i += 1;
    }
    // hash and reduce into field
    let next_previous = keccak256(transcript);

    let mut next_previous_field: u256 = 0;
    asm (rA: next_previous_field, rB: next_previous, rC: ZERO, rD: MODULUS) {
        wqam rA rB rC rD;
    };

    let (rho, unused) = split_challenge(next_previous_field);
    (rho_challenge_elements, rho, next_previous_field)
}

// 109 = (CONST_PROOF_SIZE_LOG_N - 1) * 4 + 1
pub fn generate_gemini_R_challenge(proof: Proof, prev_challenge: u256) -> ([u256;109], u256, u256) {
    let mut g_R: [u256;109] = [0u256; 109];
    let mut transcript = Bytes::new();
    g_R[0] = prev_challenge;
    transcript.append(prev_challenge.to_be_bytes());
    let mut i = 0;
    while i < CONST_PROOF_SIZE_LOG_N_MINUS_1 {
        g_R[1+i*4] = proof.gemini_fold_comms[i].x[0];
        g_R[2+i*4] = proof.gemini_fold_comms[i].x[1];
        g_R[3+i*4] = proof.gemini_fold_comms[i].y[0];
        g_R[4+i*4] = proof.gemini_fold_comms[i].y[1];
        transcript.append(proof.gemini_fold_comms[i].x[0].to_be_bytes());
        transcript.append(proof.gemini_fold_comms[i].x[1].to_be_bytes());
        transcript.append(proof.gemini_fold_comms[i].y[0].to_be_bytes());
        transcript.append(proof.gemini_fold_comms[i].y[1].to_be_bytes());
        i += 1;
    }
    // hash and reduce into field
    let next_previous = keccak256(transcript);

    let mut next_previous_field: u256 = 0;
    asm (rA: next_previous_field, rB: next_previous, rC: ZERO, rD: MODULUS) {
        wqam rA rB rC rD;
    };

    let (gemini_R, unused) = split_challenge(next_previous_field);
    (g_R, gemini_R, next_previous_field)
}

// 29 = (CONST_PROOF_SIZE_LOG_N) + 1
pub fn generate_shplonk_nu_challenge(proof: Proof, prev_challenge: u256) -> ([u256; 29], u256, u256) {
    // CONST_PROOF_SIZE_LOG_N + 1
    let mut shplonk_nu_challenge_elements: [u256; 29] = [0u256; 29];
    let mut transcript = Bytes::new();
    shplonk_nu_challenge_elements[0] = prev_challenge;
    transcript.append(prev_challenge.to_be_bytes());
    let mut i = 0;
    while i < CONST_PROOF_SIZE_LOG_N {
        shplonk_nu_challenge_elements[i+1] = proof.gemini_a_evaluations[i];
        transcript.append(proof.gemini_a_evaluations[i].to_be_bytes());
        i += 1;
    }
    let next_previous = keccak256(transcript);

    let mut next_previous_field: u256 = 0;
    asm (rA: next_previous_field, rB: next_previous, rC: ZERO, rD: MODULUS) {
        wqam rA rB rC rD;
    };

    let (shplonk_nu, unused) = split_challenge(next_previous_field);
    (shplonk_nu_challenge_elements, shplonk_nu, next_previous_field)
}

// fixed 5
pub fn generate_shplonk_z_challenge(proof: Proof, prev_challenge: u256) -> ([u256;5], u256, u256) {
    let mut shplonk_Z_challenge: [u256;5] = [0u256;5];
    let mut transcript = Bytes::new();
    shplonk_Z_challenge[0] = prev_challenge;
    shplonk_Z_challenge[1] = proof.shplonk_q.x[0];
    shplonk_Z_challenge[2] = proof.shplonk_q.x[1];
    shplonk_Z_challenge[3] = proof.shplonk_q.y[0];
    shplonk_Z_challenge[4] = proof.shplonk_q.y[1];
    let mut i = 0;
    while i < 5 {
        transcript.append(shplonk_Z_challenge[i].to_be_bytes());
        i += 1;
    }
    let next_previous = keccak256(transcript);
    let mut next_previous_field: u256 = 0;
    asm (rA: next_previous_field, rB: next_previous, rC: ZERO, rD: MODULUS) {
        wqam rA rB rC rD;
    };

    let (shplonk_Z, unused) = split_challenge(next_previous_field);
    (shplonk_Z_challenge, shplonk_Z, next_previous_field)
}

const NEG_HALF_MODULO_P: u256 = 0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000u256;

// 40 = NUMBER_OF_ENTITIES
// In Sway we use constant values for indices instead of enums
pub fn accumulate_arithmetic_relation(p: [u256; 40], domain_sep: u256) -> (u256, u256) {
    let q_arith: u256 = p[WIRE_Q_ARITH];

    // Relation 0
    let mut accum0: u256 = (q_arith.submod(3))
    .mulmod(
      p[WIRE_Q_M].mulmod(
        p[WIRE_W_R].mulmod(
          p[WIRE_W_L].mulmod(
            NEG_HALF_MODULO_P))));

    accum0 = accum0.addmod(p[WIRE_Q_L].mulmod(p[WIRE_W_L]))
      .addmod(p[WIRE_Q_R].mulmod(p[WIRE_W_R]))
      .addmod(p[WIRE_Q_O].mulmod(p[WIRE_W_O]))
      .addmod(p[WIRE_Q_4].mulmod(p[WIRE_W_4]))
      .addmod(p[WIRE_Q_C]);

    accum0 = accum0.addmod((q_arith.submod(1)).mulmod(p[WIRE_W_4_SHIFT]));
    accum0 = accum0.mulmod(q_arith);
    accum0 = accum0.mulmod(domain_sep);

    // Relation 1
    let mut accum1 = p[WIRE_W_L].addmod(p[WIRE_W_4]).submod(p[WIRE_W_L_SHIFT]).addmod(p[WIRE_Q_M]);
    accum1 = accum1.mulmod(q_arith.submod(2));
    accum1 = accum1.mulmod(q_arith.submod(1));
    accum1 = accum1.mulmod(q_arith);
    accum1 = accum1.mulmod(domain_sep);

    (accum0, accum1)
}

// 16 = PAIRING_POINTS_SIZE
pub fn compute_public_input_delta(public_inputs: [u256; 4], pairing_point_object: [u256; 16], beta: u256, gamma: u256, offset: u256) -> u256 {

    let mut numerator: u256 = 1u256;
    let mut denominator: u256 = 1u256;
    let mut numerator_acc: u256 = gamma.addmod(beta.mulmod(N.addmod(offset)));
    let mut denominator_acc: u256 = gamma.submod(beta.mulmod(offset.addmod(1u256)));

    let mut i = 0;
    while i < (NUMBER_OF_PUBLIC_INPUTS - PAIRING_POINTS_SIZE) {
        let pub_input = public_inputs[i];
        numerator = numerator.mulmod(numerator_acc.addmod(pub_input));
        denominator = denominator.mulmod(denominator_acc.addmod(pub_input));
        numerator_acc = numerator_acc.addmod(beta);
        denominator_acc = denominator_acc.submod(beta);
        i += 1;
    }

    i = 0;

    while i < PAIRING_POINTS_SIZE {
        let pub_input = pairing_point_object[i];
        numerator = numerator.mulmod(numerator_acc.addmod(pub_input));
        denominator = denominator.mulmod(denominator_acc.addmod(pub_input));
        numerator_acc = numerator_acc.addmod(beta);
        denominator_acc = denominator_acc.submod(beta);
        i += 1;
    }
    denominator = inverse(denominator);
    numerator.mulmod(denominator)
}

// 40 = NUMBER_OF_ENTITIES
pub fn accumulate_permutation_relation(
  p: [u256; 40],
  rp: RelationParameters,
  domain_sep: u256,
  public_inputs_delta: u256) -> (u256, u256) {
    let mut grand_product_numerator = 0u256;
    let mut grand_product_denominator = 0u256;

    let mut num: u256 = p[WIRE_W_L].addmod((p[WIRE_ID_1]).mulmod(rp.beta)).addmod(rp.gamma);
    num = num.mulmod(p[WIRE_W_R].addmod(p[WIRE_ID_2].mulmod(rp.beta)).addmod(rp.gamma));
    num = num.mulmod(p[WIRE_W_O].addmod(p[WIRE_ID_3].mulmod(rp.beta)).addmod(rp.gamma));
    num = num.mulmod(p[WIRE_W_4].addmod(p[WIRE_ID_4].mulmod(rp.beta)).addmod(rp.gamma));
    grand_product_numerator = num;

    let mut den: u256 = p[WIRE_W_L].addmod((p[WIRE_SIGMA_1]).mulmod(rp.beta)).addmod(rp.gamma);
    den = den.mulmod(p[WIRE_W_R].addmod(p[WIRE_SIGMA_2].mulmod(rp.beta)).addmod(rp.gamma));
    den = den.mulmod(p[WIRE_W_O].addmod(p[WIRE_SIGMA_3].mulmod(rp.beta)).addmod(rp.gamma));
    den = den.mulmod(p[WIRE_W_4].addmod(p[WIRE_SIGMA_4].mulmod(rp.beta)).addmod(rp.gamma));
    grand_product_denominator = den;

    // Contribution 2
    let mut acc2: u256 = (p[WIRE_Z_PERM].addmod(p[WIRE_LAGRANGE_FIRST])).mulmod(grand_product_numerator);
    acc2 = acc2.submod((p[WIRE_Z_PERM_SHIFT].addmod(p[WIRE_LAGRANGE_LAST].mulmod(public_inputs_delta))).mulmod(grand_product_denominator));
    acc2 = acc2.mulmod(domain_sep);

    // Contribution 3
    let acc3 = p[WIRE_LAGRANGE_LAST].mulmod(p[WIRE_Z_PERM_SHIFT]).mulmod(domain_sep);

    (acc2, acc3)
}

// 40 = NUMBER_OF_ENTITIES
pub fn accumulate_log_derivative_lookup_relation(
  p: [u256; 40],
  rp: RelationParameters,
  domain_sep: u256) -> (u256, u256) {
    let mut write_term = 0u256;
    let mut read_term = 0u256;

    write_term = p[WIRE_TABLE_1]
      .addmod(rp.gamma)
      .addmod(p[WIRE_TABLE_2].mulmod(rp.eta))
      .addmod(p[WIRE_TABLE_3].mulmod(rp.eta_two))
      .addmod(p[WIRE_TABLE_4].mulmod(rp.eta_three));

    let derived_entry_1: u256 = p[WIRE_W_L]
      .addmod(rp.gamma)
      .addmod(p[WIRE_Q_R].mulmod(p[WIRE_W_L_SHIFT]));

    let derived_entry_2: u256 = p[WIRE_W_R]
      .addmod(p[WIRE_Q_M].mulmod(p[WIRE_W_R_SHIFT]));

    let derived_entry_3: u256 = p[WIRE_W_O]
      .addmod(p[WIRE_Q_C].mulmod(p[WIRE_W_O_SHIFT]));

    read_term = derived_entry_1
      .addmod(derived_entry_2.mulmod(rp.eta))
      .addmod(derived_entry_3.mulmod(rp.eta_two))
      .addmod(p[WIRE_Q_O].mulmod(rp.eta_three));

    let read_inverse: u256 = p[WIRE_LOOKUP_INVERSES].mulmod(write_term);
    let write_inverse: u256 = p[WIRE_LOOKUP_INVERSES].mulmod(read_term);

    let inverse_exists_xor: u256 = p[WIRE_LOOKUP_READ_TAGS]
      .addmod(p[WIRE_Q_LOOKUP])
      .submod(p[WIRE_LOOKUP_READ_TAGS].mulmod(p[WIRE_Q_LOOKUP]));

    // Inverse calculated correctly relation
    let mut accumulator_none: u256 = read_term.mulmod(write_term).mulmod(p[WIRE_LOOKUP_INVERSES]);
    accumulator_none = accumulator_none.submod(inverse_exists_xor);
    accumulator_none = accumulator_none.mulmod(domain_sep);

    // Inverse
    let accumulator_one: u256 = p[WIRE_Q_LOOKUP].mulmod(read_inverse)
      .submod(p[WIRE_LOOKUP_READ_COUNTS].mulmod(write_inverse));
    (accumulator_none, accumulator_one)
}

// 40 = NUMBER_OF_ENTITIES
pub fn accumulate_delta_range_relation(
    p: [u256; 40],
    domain_sep: u256,
) -> (u256, u256, u256, u256) {
    let minus_one: u256 = MINUS_ONE;
    let minus_two: u256 = minus_one.submod(1u256);
    let minus_three: u256 = minus_one.submod(2u256);

    // Wire deltas
    let delta_1: u256 = p[WIRE_W_R].submod(p[WIRE_W_L]);
    let delta_2: u256 = p[WIRE_W_O].submod(p[WIRE_W_R]);
    let delta_3: u256 = p[WIRE_W_4].submod(p[WIRE_W_O]);
    let delta_4: u256 = p[WIRE_W_L_SHIFT].submod(p[WIRE_W_4]);

    // Contribution 6
    let mut acc6: u256 = delta_1;
    acc6 = acc6.mulmod(delta_1.addmod(minus_one));
    acc6 = acc6.mulmod(delta_1.addmod(minus_two));
    acc6 = acc6.mulmod(delta_1.addmod(minus_three));
    acc6 = acc6.mulmod(p[WIRE_Q_RANGE]);
    acc6 = acc6.mulmod(domain_sep);

    // Contribution 7
    let mut acc7: u256 = delta_2;
    acc7 = acc7.mulmod(delta_2.addmod(minus_one));
    acc7 = acc7.mulmod(delta_2.addmod(minus_two));
    acc7 = acc7.mulmod(delta_2.addmod(minus_three));
    acc7 = acc7.mulmod(p[WIRE_Q_RANGE]);
    acc7 = acc7.mulmod(domain_sep);

    // Contribution 8
    let mut acc8: u256 = delta_3;
    acc8 = acc8.mulmod(delta_3.addmod(minus_one));
    acc8 = acc8.mulmod(delta_3.addmod(minus_two));
    acc8 = acc8.mulmod(delta_3.addmod(minus_three));
    acc8 = acc8.mulmod(p[WIRE_Q_RANGE]);
    acc8 = acc8.mulmod(domain_sep);

    // Contribution 9
    let mut acc9: u256 = delta_4;
    acc9 = acc9.mulmod(delta_4.addmod(minus_one));
    acc9 = acc9.mulmod(delta_4.addmod(minus_two));
    acc9 = acc9.mulmod(delta_4.addmod(minus_three));
    acc9 = acc9.mulmod(p[WIRE_Q_RANGE]);
    acc9 = acc9.mulmod(domain_sep);

    (acc6, acc7, acc8, acc9)
}

// 40 = NUMBER_OF_ENTITIES
pub fn accumulate_elliptic_relation(
    p: [u256; 40],
    domain_sep: u256,
) -> (u256, u256) {
    // elliptic parameters
    let x1 = p[WIRE_W_R];
    let y1 = p[WIRE_W_O];

    let x2 = p[WIRE_W_L_SHIFT];
    let y2 = p[WIRE_W_4_SHIFT];
    let y3 = p[WIRE_W_O_SHIFT];
    let x3 = p[WIRE_W_R_SHIFT];

    let q_sign = p[WIRE_Q_L];
    let q_is_double = p[WIRE_Q_M];
    let q_elliptic = p[WIRE_Q_ELLIPTIC];

    let x_diff = x2.submod(x1);
    let y1_sqr = y1.mulmod(y1);

    let one_minus_q_is_double = (1u256.submod(q_is_double));

    // Contribution 10 point addition, x-coordinate check
    let y2_sqr = y2.mulmod(y2);
    let y1y2_q = y1.mulmod(y2).mulmod(q_sign);
    let mut x_add_identity =
        (x3.addmod(x2).addmod(x1))
        .mulmod(x_diff.mulmod(x_diff));
    x_add_identity = x_add_identity
        .submod(y2_sqr)
        .submod(y1_sqr)
        .addmod(y1y2_q).addmod(y1y2_q);

    let mut eval10 =
        x_add_identity
        .mulmod(domain_sep)
        .mulmod(q_elliptic)
        .mulmod(one_minus_q_is_double);

    // Contribution 11 point addition, x-coordinate check
    let y1_plus_y3 = y1.addmod(y3);
    let y_diff = y2.mulmod(q_sign).submod(y1);
    let y_add_identity =
        y1_plus_y3.mulmod(x_diff)
        .addmod( (x3.submod(x1)).mulmod(y_diff));

    let mut eval11 =
        y_add_identity
        .mulmod(domain_sep)
        .mulmod(q_elliptic)
        .mulmod(one_minus_q_is_double);

    // Contribution 10 point doubling, x-coordinate check
    let x_pow_4 = (y1_sqr.addmod(17u256)).mulmod(x1);
    let mut y1_sqr_mul_4 = y1_sqr.addmod(y1_sqr);
    y1_sqr_mul_4 = y1_sqr_mul_4.addmod(y1_sqr_mul_4);
    let x1_pow_4_mul_9 = x_pow_4.mulmod(9u256);

    let x_double_identity =
        (x3.addmod(x1).addmod(x1)).mulmod(y1_sqr_mul_4)
        .submod(x1_pow_4_mul_9);

    eval10 = eval10.addmod(
        x_double_identity
            .mulmod(domain_sep)
            .mulmod(q_elliptic)
            .mulmod(q_is_double)
    );

    // Contribution 11 point doubling, y-coordinate check
    let x1_sqr_mul_3 = (x1.addmod(x1).addmod(x1)).mulmod(x1);
    let y_double_identity =
        x1_sqr_mul_3.mulmod(x1.submod(x3))
        .submod( (y1.addmod(y1)).mulmod(y1.addmod(y3)));

    eval11 = eval11.addmod(
        y_double_identity
            .mulmod(domain_sep)
            .mulmod(q_elliptic)
            .mulmod(q_is_double)
    );

    (eval10, eval11)
}

const SUBLIMB_SHIFT: u256 = 0x4000u256;
const LIMB_SIZE:    u256 = 0x100000000000000000u256;

// 40 = NUMBER_OF_ENTITIES
pub fn accumulate_auxiliary_relation(
    p: [u256; 40],
    rp: RelationParameters,
    domain_sep: u256,
) -> (u256, u256, u256, u256, u256, u256) {
    let qL = p[WIRE_Q_L];
    let qR = p[WIRE_Q_R];
    let qO = p[WIRE_Q_O];
    let qM = p[WIRE_Q_M];
    let q4 = p[WIRE_Q_4];
    let qAux = p[WIRE_Q_AUX];
    let qArith = p[WIRE_Q_ARITH];

    let qLR = qL.mulmod(qR);
    let auxSep = qAux.mulmod(domain_sep);

    // Non-native field arithmetic
    let mut limb_subproduct =
        (p[WIRE_W_L].mulmod(p[WIRE_W_R_SHIFT])).addmod(p[WIRE_W_L_SHIFT].mulmod(p[WIRE_W_R]));

    let mut nnf_gate_2 =
          (p[WIRE_W_L].mulmod(p[WIRE_W_4]))
        .addmod(p[WIRE_W_R].mulmod(p[WIRE_W_O]))
        .submod(p[WIRE_W_O_SHIFT]);
    nnf_gate_2 = nnf_gate_2.mulmod(LIMB_SIZE);
    nnf_gate_2 = nnf_gate_2.submod(p[WIRE_W_4_SHIFT]);
    nnf_gate_2 = nnf_gate_2.addmod(limb_subproduct);
    nnf_gate_2 = nnf_gate_2.mulmod(q4);

    limb_subproduct = limb_subproduct.mulmod(LIMB_SIZE);
    limb_subproduct = limb_subproduct.addmod(p[WIRE_W_L_SHIFT].mulmod(p[WIRE_W_R_SHIFT]));

    let mut nnf_gate_1 = limb_subproduct.submod(p[WIRE_W_O].addmod(p[WIRE_W_4]));
    nnf_gate_1 = nnf_gate_1.mulmod(qO);

    let mut nnf_gate_3 = limb_subproduct.addmod(p[WIRE_W_4]);
    nnf_gate_3 = nnf_gate_3.submod(p[WIRE_W_O_SHIFT].addmod(p[WIRE_W_4_SHIFT]));
    nnf_gate_3 = nnf_gate_3.mulmod(qM);

    let mut non_native_field_identity = nnf_gate_1.addmod(nnf_gate_2).addmod(nnf_gate_3);
    non_native_field_identity = non_native_field_identity.mulmod(qR);

    // ((((w2' * 2^14 + w1') * 2^14 + w3) * 2^14 + w2) * 2^14 + w1 - w4) * qm
    let mut limb_acc_1 = p[WIRE_W_R_SHIFT].mulmod(SUBLIMB_SHIFT);
    limb_acc_1 = (limb_acc_1.addmod(p[WIRE_W_L_SHIFT])).mulmod(SUBLIMB_SHIFT);
    limb_acc_1 = (limb_acc_1.addmod(p[WIRE_W_O])).mulmod(SUBLIMB_SHIFT);
    limb_acc_1 = (limb_acc_1.addmod(p[WIRE_W_R])).mulmod(SUBLIMB_SHIFT);
    limb_acc_1 = (limb_acc_1.addmod(p[WIRE_W_L]).submod(p[WIRE_W_4])).mulmod(q4);

    // ((((w3' * 2^14 + w2') * 2^14 + w1') * 2^14 + w4) * 2^14 + w3 - w4') * qm
    let mut limb_acc_2 = p[WIRE_W_O_SHIFT].mulmod(SUBLIMB_SHIFT);
    limb_acc_2 = (limb_acc_2.addmod(p[WIRE_W_R_SHIFT])).mulmod(SUBLIMB_SHIFT);
    limb_acc_2 = (limb_acc_2.addmod(p[WIRE_W_L_SHIFT])).mulmod(SUBLIMB_SHIFT);
    limb_acc_2 = (limb_acc_2.addmod(p[WIRE_W_4])).mulmod(SUBLIMB_SHIFT);
    limb_acc_2 = (limb_acc_2.addmod(p[WIRE_W_O]).submod(p[WIRE_W_4_SHIFT])).mulmod(qM);

    let mut limb_acc_identity = limb_acc_1.addmod(limb_acc_2);
    limb_acc_identity = limb_acc_identity.mulmod(qO);

    // Memory record check
    // qc + w1*eta + w2*eta_two + w3*eta_three − w4
    let mut memory_record_check = p[WIRE_W_O].mulmod(rp.eta_three);
    memory_record_check = memory_record_check.addmod(p[WIRE_W_R].mulmod(rp.eta_two));
    memory_record_check = memory_record_check.addmod(p[WIRE_W_L].mulmod(rp.eta));
    memory_record_check = memory_record_check.addmod(p[WIRE_Q_C]);
    let partial_record_check = memory_record_check;
    memory_record_check = memory_record_check.submod(p[WIRE_W_4]);

    let index_delta  = p[WIRE_W_L_SHIFT].submod(p[WIRE_W_L]);
    let record_delta = p[WIRE_W_4_SHIFT].submod(p[WIRE_W_4]);

    let index_is_monotonic =
        (index_delta.mulmod(index_delta)).submod(index_delta);

    let adj_vals_if_adj_idx =
        ((index_delta.mulmod(MINUS_ONE)).addmod(1u256)).mulmod(record_delta);

    let eval13 =
        adj_vals_if_adj_idx.mulmod(qLR).mulmod(auxSep);
    let eval14 =
        index_is_monotonic.mulmod(qLR).mulmod(auxSep);

    let rom_consistency_check_identity = memory_record_check.mulmod(qLR);

    // RAM consistency
    let access_type = p[WIRE_W_4].submod(partial_record_check);
    let access_check = (access_type.mulmod(access_type)).submod(access_type);

    let mut next_gate_access_type =
          (p[WIRE_W_O_SHIFT].mulmod(rp.eta_three))
        .addmod(p[WIRE_W_R_SHIFT].mulmod(rp.eta_two))
        .addmod(p[WIRE_W_L_SHIFT].mulmod(rp.eta));
    next_gate_access_type = p[WIRE_W_4_SHIFT].submod(next_gate_access_type);

    let value_delta = p[WIRE_W_O_SHIFT].submod(p[WIRE_W_O]);

    let mut adj_vals_if_adj_idx_and_next_is_read =
        (index_delta.mulmod(MINUS_ONE)).addmod(1u256);
    adj_vals_if_adj_idx_and_next_is_read = adj_vals_if_adj_idx_and_next_is_read.mulmod(value_delta);
    adj_vals_if_adj_idx_and_next_is_read = adj_vals_if_adj_idx_and_next_is_read.mulmod((next_gate_access_type.mulmod(MINUS_ONE)).addmod(1u256));

    let next_gate_access_is_bool =
        (next_gate_access_type.mulmod(next_gate_access_type)).submod(next_gate_access_type);

    let eval15 = adj_vals_if_adj_idx_and_next_is_read.mulmod(qArith).mulmod(auxSep);
    let eval16 = index_is_monotonic.mulmod(qArith).mulmod(auxSep);
    let eval17 = next_gate_access_is_bool.mulmod(qArith).mulmod(auxSep);

    let ram_consistency_check_identity = access_check.mulmod(qArith);

    // Let delta_index = index_{i + 1} - index_{i}
    // Iff delta_index == 0, timestamp_check = timestamp_{i + 1} - timestamp_i
    // Else timestamp_check = 0
    let timestamp_delta = p[WIRE_W_R_SHIFT].submod(p[WIRE_W_R]);
    let mut ram_timestamp_check_identity =
        (index_delta.mulmod(MINUS_ONE)).addmod(1u256);
    ram_timestamp_check_identity = ram_timestamp_check_identity.mulmod(timestamp_delta);
    ram_timestamp_check_identity = ram_timestamp_check_identity.submod(p[WIRE_W_O]);

    let mut memory_identity =
          rom_consistency_check_identity;
    memory_identity = memory_identity.addmod(ram_timestamp_check_identity.mulmod(q4.mulmod(qL)));
    memory_identity = memory_identity.addmod(memory_record_check.mulmod(qM.mulmod(qL)));
    memory_identity = memory_identity.addmod(ram_consistency_check_identity);

    // (deg 3 or 9) + (deg 4) + (deg 3)
    let auxiliary_identity =
        memory_identity.addmod(non_native_field_identity).addmod(limb_acc_identity);

    let eval12 = auxiliary_identity.mulmod(auxSep);

    (eval12, eval13, eval14, eval15, eval16, eval17)
}

// 40 = NUMBER_OF_ENTITIES
pub fn accumulate_poseidon_external_relation(
    p: [u256; 40],
    domain_sep: u256,
) -> (u256, u256, u256, u256) {
    let s1 = p[WIRE_W_L].addmod(p[WIRE_Q_L]);
    let s2 = p[WIRE_W_R].addmod(p[WIRE_Q_R]);
    let s3 = p[WIRE_W_O].addmod(p[WIRE_Q_O]);
    let s4 = p[WIRE_W_4].addmod(p[WIRE_Q_4]);

    let u1 = s1.mulmod(s1).mulmod(s1).mulmod(s1).mulmod(s1);
    let u2 = s2.mulmod(s2).mulmod(s2).mulmod(s2).mulmod(s2);

    let u3 = s3.mulmod(s3).mulmod(s3).mulmod(s3).mulmod(s3);
    let u4 = s4.mulmod(s4).mulmod(s4).mulmod(s4).mulmod(s4);

    // matrix mul v = M_E * u with 14 additions
    let t0 = u1.addmod(u2); // u_1 + u_2
    let t1 = u3.addmod(u4); // u_3 + u_4

    let mut t2 = u2.addmod(u2); // 2u_2
    t2 = t2.addmod(t1); // 2u_2 + u_3 + u_4

    let mut t3 = u4.addmod(u4); // 2u_4
    t3 = t3.addmod(t0); // u_1 + u_2 + 2u_4

    let mut v4 = t1.addmod(t1);
    v4 = v4.addmod(v4).addmod(t3); // u_1 + u_2 + 4u_3 + 6u_4

    let mut v2 = t0.addmod(t0);
    v2 = v2.addmod(v2).addmod(t2); // 4u_1 + 6u_2 + u_3 + u_4

    let v1 = t3.addmod(v2); // 5u_1 + 7u_2 + u_3 + 3u_4
    let v3 = t2.addmod(v4); // u_1 + 3u_2 + 5u_3 + 7u_4

    let q_pos_by_scaling = p[WIRE_Q_POSEIDON2_EXTERNAL].mulmod(domain_sep);

    let eval18 = q_pos_by_scaling.mulmod(v1.submod(p[WIRE_W_L_SHIFT]));
    let eval19 = q_pos_by_scaling.mulmod(v2.submod(p[WIRE_W_R_SHIFT]));
    let eval20 = q_pos_by_scaling.mulmod(v3.submod(p[WIRE_W_O_SHIFT]));
    let eval21 = q_pos_by_scaling.mulmod(v4.submod(p[WIRE_W_4_SHIFT]));

    (eval18, eval19, eval20, eval21)
}

// 40 = NUMBER_OF_ENTITIES
pub fn accumulate_poseidon_internal_relation(
    p: [u256; 40],
    domain_sep: u256,
) -> (u256, u256, u256, u256) {
    let INTERNAL_MATRIX_DIAGONAL: [u256; 4] = [
        0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7u256,
        0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740bu256,
        0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15u256,
        0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428bu256
    ];

    // add round constants
    let s1 = p[WIRE_W_L].addmod(p[WIRE_Q_L]);

    // apply s-box round
    let u1 = s1.mulmod(s1).mulmod(s1).mulmod(s1).mulmod(s1);
    let u2 = p[WIRE_W_R];
    let u3 = p[WIRE_W_O];
    let u4 = p[WIRE_W_4];

    // matrix mul with v = M_I * u 4 muls and 7 additions
    let u_sum = u1.addmod(u2).addmod(u3).addmod(u4);

    let q_pos_by_scaling = p[WIRE_Q_POSEIDON2_INTERNAL].mulmod(domain_sep);

    let v1 = u1.mulmod(INTERNAL_MATRIX_DIAGONAL[0]).addmod(u_sum);
    let eval22 = q_pos_by_scaling.mulmod(v1.submod(p[WIRE_W_L_SHIFT]));

    let v2 = u2.mulmod(INTERNAL_MATRIX_DIAGONAL[1]).addmod(u_sum);
    let eval23 = q_pos_by_scaling.mulmod(v2.submod(p[WIRE_W_R_SHIFT]));

    let v3 = u3.mulmod(INTERNAL_MATRIX_DIAGONAL[2]).addmod(u_sum);
    let eval24 = q_pos_by_scaling.mulmod(v3.submod(p[WIRE_W_O_SHIFT]));

    let v4 = u4.mulmod(INTERNAL_MATRIX_DIAGONAL[3]).addmod(u_sum);
    let eval25 = q_pos_by_scaling.mulmod(v4.submod(p[WIRE_W_4_SHIFT]));

    (eval22, eval23, eval24, eval25)
}

// 26 = NUMBER_OF_SUBRELATIONS
// 25 = NUMBER_OF_ALPHAS
pub fn scale_and_batch_subrelations(
    evaluations: [u256; 26],
    subrelation_challenges: [u256; 25],
) -> u256 {
    let mut accumulator = evaluations[0];

    let mut i = 1;
    while i < NUMBER_OF_SUBRELATIONS {
        accumulator = accumulator.addmod(evaluations[i].mulmod(subrelation_challenges[i - 1]));
        i += 1;
    }

    accumulator
}

// 40 = NUMBER_OF_ENTITIES
// 25 = NUMBER_OF_ALPHAS
pub fn accumulate_relation_evaluations(
  p: [u256; 40],
  rp: RelationParameters,
  alphas: [u256; 25],
  pow_partial_evaluation: u256) -> u256 {
    let (evals_0, evals_1) = accumulate_arithmetic_relation(p, pow_partial_evaluation);
    let (evals_2, evals_3): (u256, u256) = accumulate_permutation_relation(p, rp, pow_partial_evaluation, rp.public_inputs_delta);
    let (evals_4, evals_5): (u256, u256) = accumulate_log_derivative_lookup_relation(p, rp, pow_partial_evaluation);
    let (evals_6, evals_7, evals_8, evals_9): (u256, u256, u256, u256) = accumulate_delta_range_relation(p, pow_partial_evaluation);
    let (evals_10, evals_11): (u256, u256) = accumulate_elliptic_relation(p, pow_partial_evaluation);
    let (evals_12, evals_13, evals_14, evals_15, evals_16, evals_17): (u256, u256, u256, u256, u256, u256) = accumulate_auxiliary_relation(p, rp, pow_partial_evaluation);
    let (evals_18, evals_19, evals_20, evals_21): (u256, u256, u256, u256) = accumulate_poseidon_external_relation(p, pow_partial_evaluation);
    let (evals_22, evals_23, evals_24, evals_25): (u256, u256, u256, u256) = accumulate_poseidon_internal_relation(p, pow_partial_evaluation);
    let mut evaluations: [u256; 26] = [0u256; 26];
    evaluations[0]  = evals_0;
    evaluations[1]  = evals_1;
    evaluations[2]  = evals_2;
    evaluations[3]  = evals_3;
    evaluations[4]  = evals_4;
    evaluations[5]  = evals_5;
    evaluations[6]  = evals_6;
    evaluations[7]  = evals_7;
    evaluations[8]  = evals_8;
    evaluations[9]  = evals_9;
    evaluations[10] = evals_10;
    evaluations[11] = evals_11;
    evaluations[12] = evals_12;
    evaluations[13] = evals_13;
    evaluations[14] = evals_14;
    evaluations[15] = evals_15;
    evaluations[16] = evals_16;
    evaluations[17] = evals_17;
    evaluations[18] = evals_18;
    evaluations[19] = evals_19;
    evaluations[20] = evals_20;
    evaluations[21] = evals_21;
    evaluations[22] = evals_22;
    evaluations[23] = evals_23;
    evaluations[24] = evals_24;
    evaluations[25] = evals_25;

    scale_and_batch_subrelations(evaluations, alphas)
}

// 8 = BATCHED_RELATION_PARTIAL_LENGTH
pub fn compute_next_target_sum(
    round_univariates: [u256; 8],
    round_challenge: u256,
) -> u256 {
    let BARYCENTRIC_LAGRANGE_DENOMINATORS: [u256; 8] = [ // BATCHED_RELATION_PARTIAL_LENGTH
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51u256,
        0x02d0u256,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff11u256,
        0x0090u256,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff71u256,
        0x00f0u256,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31u256,
        0x13b0u256
    ];

    // Performing Barycentric evaluations
    // Compute B(x)
    let mut numerator_value = 1u256;
    let mut i = 0;
    while i < BATCHED_RELATION_PARTIAL_LENGTH {
        numerator_value = numerator_value.mulmod(
            round_challenge.submod(i.as_u256())
        );
        i += 1;
    }

    // Calculate domain size N of inverses
    let mut denominator_inverses: [u256; 8] = [0u256; 8]; // BATCHED_RELATION_PARTIAL_LENGTH
    i = 0;
    while i < BATCHED_RELATION_PARTIAL_LENGTH {
        let mut inv = BARYCENTRIC_LAGRANGE_DENOMINATORS[i];
        inv = inv.mulmod(round_challenge.submod(i.as_u256()));
        inv = inverse(inv);
        denominator_inverses[i] = inv;
        i += 1;
    }

    let mut target_sum = 0u256;
    i = 0;
    while i < BATCHED_RELATION_PARTIAL_LENGTH {
        let term = round_univariates[i].mulmod(denominator_inverses[i]);
        target_sum = target_sum.addmod(term);
        i += 1;
    }

    // Scale the sum by the value of B(x)
    target_sum = target_sum.mulmod(numerator_value);

    target_sum
}

pub fn partially_evaluate_pow(
    gate_challenge: u256,
    current_evaluation: u256,
    round_challenge: u256,
) -> u256 {
    let univariate_eval = 1u256.addmod(
        round_challenge.mulmod(
            gate_challenge.submod(1u256)
        )
    );
    current_evaluation.mulmod(univariate_eval)
}

// 8 = BATCHED_RELATION_PARTIAL_LENGTH
pub fn check_sum(
    round_univariate: [u256; 8],
    round_target: u256,
) -> bool {
    let total_sum = round_univariate[0].addmod(round_univariate[1]);
    total_sum == round_target
}

pub fn verify_sumcheck(
    proof: Proof,
    transcript: Transcript,
) -> bool {
    let mut round_target = 0u256;
    let mut pow_partial_evaluation = 1u256;

    let mut round = 0;
    while round.as_u256() < LOG_N {
        let round_univariate = proof.sumcheck_univariates[round];

        let valid = check_sum(round_univariate, round_target);
        if !valid {
            panic VerifierErrors::SumcheckFailed;
        }

        let round_challenge = transcript.sumcheck_u_challenges[round];

        // Update the round target for the next round
        round_target = compute_next_target_sum(round_univariate, round_challenge);

        pow_partial_evaluation = partially_evaluate_pow(
            transcript.gate_challenges[round],
            pow_partial_evaluation,
            round_challenge
        );

        round += 1;
    }

    // Last round
    let grand_honk_relation_sum = accumulate_relation_evaluations(
        proof.sumcheck_evaluations,
        transcript.relation_parameters,
        transcript.alphas,
        pow_partial_evaluation
    );

    grand_honk_relation_sum == round_target
}

// 28 = CONST_PROOF_SIZE_LOG_N
pub fn compute_squares(r: u256) -> [u256; 28] {
    let mut squares: [u256; 28] = [0u256; 28];
    squares[0] = r;

    let mut i = 1;
    while i < CONST_PROOF_SIZE_LOG_N {
        squares[i] = squares[i - 1].mulmod(squares[i - 1]);
        i += 1;
    }

    squares
}

// 28 = CONST_PROOF_SIZE_LOG_N
pub fn compute_fold_pos_evaluations(
    sumcheck_u_challenges: [u256; 28],
    batched_eval_accumulator: u256,
    gemini_evaluations: [u256; 28],
    gemini_eval_challenge_powers: [u256; 28],
    log_size: u256
) -> [u256; 28] {
    let mut fold_pos_evaluations: [u256; 28] = [0; 28];
    let mut batched_eval_accumulator_updated = batched_eval_accumulator;
    let mut i = CONST_PROOF_SIZE_LOG_N;
    while i > 0 {
        let idx = i - 1;

        let challenge_power = gemini_eval_challenge_powers[idx];
        let u = sumcheck_u_challenges[idx];

        let term1 = challenge_power.mulmod(batched_eval_accumulator_updated).mulmod(2);
        let term2 = gemini_evaluations[idx].mulmod((challenge_power.mulmod(1u256.submod(u))).submod(u));

        let mut batched_eval_round_acc = term1.submod(term2);

        let denom = challenge_power.mulmod((1u256.submod(u))).addmod(u);
        let denom_inv = inverse(denom);

        batched_eval_round_acc = batched_eval_round_acc.mulmod(denom_inv);

        if (i.as_u256() <= log_size) {
            batched_eval_accumulator_updated = batched_eval_round_acc;
            fold_pos_evaluations[idx] = batched_eval_round_acc;
        }

        i -= 1;
    }

    fold_pos_evaluations
}

pub fn pairing(
    P_0: G1Point,
    P_1: G1Point,
) -> bool {
      // Serialize inputs for EPAR
      let mut pairing_input: [u256; 12] = [0; 12];

      // Pairing input: P_0(already negated), [1]_2
      pairing_input[0] = P_0.x;
      pairing_input[1] = P_0.y;
      // g2: [[x1, x0], [y1, y0]]
      pairing_input[3] = G2x1;
      pairing_input[2] = G2x2;
      pairing_input[5] = G2y1;
      pairing_input[4] = G2y2;

      // Pairing input: P_1, X2
      pairing_input[6] = P_1.x;
      pairing_input[7] = P_1.y;
      // g2: [[x1, x0], [y1, y0]]
      pairing_input[9] = X2x1;
      pairing_input[8] = X2x2;
      pairing_input[11] = X2y1;
      pairing_input[10] = X2y2;

      // Perform pairing check
      let curve_id: u32 = 0;
      let groups_of_points: u32 = 2;

      let result: u32 = asm(rA, rB: curve_id, rC: groups_of_points, rD: pairing_input) {
          epar rA rB rC rD;
          rA: u32
      };

      result != 0
}

pub fn verify_shplemini(proof: Proof, vk: VerificationKey, tp: Transcript) -> bool {
    // - Compute vector (r, r², ... , r²⁽ⁿ⁻¹⁾), where n = log_circuit_size
    // 28 = CONST_PROOF_SIZE_LOG_N
    let powers_of_evaluation_challenge: [u256; 28] = compute_squares(tp.gemini_r);
    // Arrays hold values that will be linearly combined for the gemini and shplonk batch openings
    let mut scalars: [u256; 70] = [0u256; 70]; // 70 = 40 + 28 + 2 = NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 2
    let mut commitments: [G1Point; 70] = [G1Point { x: 0u256, y: 0u256 }; 70]; // 70 = NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 2

    let pos_inverted_denominator: u256 = inverse(tp.shplonk_z.submod(powers_of_evaluation_challenge[0]));
    let neg_inverted_denominator: u256 = inverse(tp.shplonk_z.addmod(powers_of_evaluation_challenge[0]));

    let unshifted_scalar: u256 = pos_inverted_denominator.addmod(tp.shplonk_nu.mulmod(neg_inverted_denominator));
    let shifted_scalar: u256 = inverse(tp.gemini_r).mulmod(
        pos_inverted_denominator.submod(tp.shplonk_nu.mulmod(neg_inverted_denominator))
    );

    scalars[0] = 1u256;
    commitments[0] = convert_proof_point(proof.shplonk_q);

    let mut batching_challenge: u256 = 1u256;
    let mut batched_evaluation: u256 = 0u256;

    let mut i = 1;
    while i <= NUMBER_UNSHIFTED {
        scalars[i] = (0u256.submod(unshifted_scalar)).mulmod(batching_challenge);
        batched_evaluation = batched_evaluation.addmod(proof.sumcheck_evaluations[i - 1].mulmod(batching_challenge));
        batching_challenge = batching_challenge.mulmod(tp.rho);
        i += 1;
    }

    i = NUMBER_UNSHIFTED + 1;
    while i <= NUMBER_OF_ENTITIES {
        scalars[i] = (0u256.submod(shifted_scalar)).mulmod(batching_challenge);
        batched_evaluation = batched_evaluation.addmod(proof.sumcheck_evaluations[i-1].mulmod(batching_challenge));
        batching_challenge = batching_challenge.mulmod(tp.rho);
        i += 1;
    }

    commitments[1] = vk.qm;
    commitments[2] = vk.qc;
    commitments[3] = vk.ql;
    commitments[4] = vk.qr;
    commitments[5] = vk.qo;
    commitments[6] = vk.q4;
    commitments[7] = vk.q_lookup;
    commitments[8] = vk.q_arith;
    commitments[9] = vk.q_delta_range;
    commitments[10] = vk.q_elliptic;
    commitments[11] = vk.q_aux;
    commitments[12] = vk.q_poseidon2_external;
    commitments[13] = vk.q_poseidon2_internal;
    commitments[14] = vk.s1;
    commitments[15] = vk.s2;
    commitments[16] = vk.s3;
    commitments[17] = vk.s4;
    commitments[18] = vk.id1;
    commitments[19] = vk.id2;
    commitments[20] = vk.id3;
    commitments[21] = vk.id4;
    commitments[22] = vk.t1;
    commitments[23] = vk.t2;
    commitments[24] = vk.t3;
    commitments[25] = vk.t4;
    commitments[26] = vk.lagrange_first;
    commitments[27] = vk.lagrange_last;
    // Accumulate proof points
    commitments[28] = convert_proof_point(proof.w1);
    commitments[29] = convert_proof_point(proof.w2);
    commitments[30] = convert_proof_point(proof.w3);
    commitments[31] = convert_proof_point(proof.w4);
    commitments[32] = convert_proof_point(proof.z_perm);
    commitments[33] = convert_proof_point(proof.lookup_inverses);
    commitments[34] = convert_proof_point(proof.lookup_read_counts);
    commitments[35] = convert_proof_point(proof.lookup_read_tags);
    // to be Shifted
    commitments[36] = convert_proof_point(proof.w1);
    commitments[37] = convert_proof_point(proof.w2);
    commitments[38] = convert_proof_point(proof.w3);
    commitments[39] = convert_proof_point(proof.w4);
    commitments[40] = convert_proof_point(proof.z_perm);
    // Add contributions from A₀(r) and A₀(-r) to constant_term_accumulator:
    // Compute the evaluations A_l(r^{2^l}) for l = 0, ..., logN - 1
    // 28 = CONST_PROOF_SIZE_LOG_N
    let fold_pos_evaluations: [u256; 28] = compute_fold_pos_evaluations(
        tp.sumcheck_u_challenges,
        batched_evaluation,
        proof.gemini_a_evaluations,
        powers_of_evaluation_challenge,
        LOG_N
    );

    // Compute the Shplonk constant term contributions from A₀(±r)
    let mut constant_term_accumulator: u256 = fold_pos_evaluations[0].mulmod(pos_inverted_denominator);
    constant_term_accumulator = constant_term_accumulator.addmod(
        proof.gemini_a_evaluations[0].mulmod(tp.shplonk_nu).mulmod(neg_inverted_denominator)
    );
    batching_challenge = tp.shplonk_nu.mulmod(tp.shplonk_nu);

    // Compute Shplonk constant term contributions from Aₗ(±r^{2ˡ}) for l = 1, ..., m-1;
    // Compute scalar multipliers for each fold commitment
    let mut scaling_factor_pos: u256 = 0u256;
    let mut scaling_factor_neg: u256 = 0u256;
    i = 0;
    while i < CONST_PROOF_SIZE_LOG_N - 1 {
        let dummy_round = i.as_u256() >= (LOG_N - 1);
        if !dummy_round {
            // Update inverted denominators
            let pos_inverted_denominator = inverse(tp.shplonk_z.submod(powers_of_evaluation_challenge[i + 1]));
            let neg_inverted_denominator = inverse(tp.shplonk_z.addmod(powers_of_evaluation_challenge[i + 1]));

            // Compute the scalar multipliers for Aₗ(± r^{2ˡ}) and [Aₗ]
            scaling_factor_pos = batching_challenge.mulmod(pos_inverted_denominator);
            scaling_factor_neg = batching_challenge.mulmod(tp.shplonk_nu).mulmod(neg_inverted_denominator);
            // [Aₗ] is multiplied by -v^{2l}/(z-r^{2^l}) - v^{2l+1} /(z+ r^{2^l})
            scalars[NUMBER_OF_ENTITIES + 1 + i] = (0u256.submod(scaling_factor_neg)).addmod(0u256.submod(scaling_factor_pos));

            // Accumulate the const term contribution given by
            // v^{2l} * Aₗ(r^{2ˡ}) /(z-r^{2^l}) + v^{2l+1} * Aₗ(-r^{2ˡ}) /(z+ r^{2^l})
            let mut accum_contribution = scaling_factor_neg.mulmod(proof.gemini_a_evaluations[i + 1]);
            accum_contribution = accum_contribution.addmod(scaling_factor_pos.mulmod(fold_pos_evaluations[i + 1]));
            constant_term_accumulator = constant_term_accumulator.addmod(accum_contribution);
            // Update the running power of v
            batching_challenge = batching_challenge.mulmod(tp.shplonk_nu).mulmod(tp.shplonk_nu);
        }
        // NUMBER_OF_ENTITIES
        commitments[NUMBER_OF_ENTITIES + 1 + i] = convert_proof_point(proof.gemini_fold_comms[i]);
        i += 1;
    }
    // Finalise the batch opening claim
    // NUMBER_OF_ENTITIES+CONST_PROOF_SIZE_LOG_N
    commitments[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N] = G1Point { x: 1u256, y: 2u256 };
    scalars[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N] = constant_term_accumulator;

    let quotient_commitment: G1Point = convert_proof_point(proof.kzg_quotient);
    // NUMBER_OF_ENTITIES+CONST_PROOF_SIZE_LOG_N+1
    commitments[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 1] = quotient_commitment;
    scalars[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 1] = tp.shplonk_z; // evaluation challenge

    let p_0: G1Point = batch_mul(commitments, scalars);
    // Use the EC group order, F_q, to negate
    let neg_y: u256 = Q.submod(quotient_commitment.y);
    let p_1 = G1Point {
        x: quotient_commitment.x,
        y: neg_y
    };
    pairing(p_0, p_1)
}

pub fn verify(p: Proof, vk: VerificationKey, public_inputs: [u256; 4]) -> bool {
    let expected_pub_inputs: u64 = NUMBER_OF_PUBLIC_INPUTS - PAIRING_POINTS_SIZE;
    if expected_pub_inputs != 4u64 {
        panic VerifierErrors::PublicInputsLengthWrong;
    }

    // Generate the fiat shamir challenges for the whole protocol
    // TODO(https://github.com/AztecProtocol/barretenberg/issues/1281): Add pubInputsOffset to VK or remove entirely.
    // Now pubInputsOffset is fixed to 1
    let mut t: Transcript = generate_transcript(p, public_inputs, vk.circuit_size, 1u256);

    // Derive public input delta
    // TODO(https://github.com/AztecProtocol/barretenberg/issues/1281): Add pubInputsOffset to VK or remove entirely.
    // Now pubInputsOffset is fixed to 1
    t.relation_parameters.public_inputs_delta = compute_public_input_delta(
        public_inputs,
        p.pairing_point_object,
        t.relation_parameters.beta,
        t.relation_parameters.gamma,
        1u256, // pubInputsOffset
    );

    // Sumcheck
    let sumcheck_verified: bool = verify_sumcheck(p, t);
    if !sumcheck_verified {
        panic VerifierErrors::SumcheckFailed;
    }

    let shplemini_verified: bool = verify_shplemini(p, vk, t);
    if !shplemini_verified {
        panic VerifierErrors::ShpleminiFailed;
    }

    sumcheck_verified && shplemini_verified
}

abi MyContract {
    fn verify_proof(proof: Proof, public_inputs: [u256; 4]) -> bool;
}

impl MyContract for Contract {
    fn verify_proof(proof: Proof, public_inputs: [u256; 4]) -> bool {
        let vk: VerificationKey = load_vk();
        let res: bool = verify(
            proof,
            vk,
            public_inputs
        );
        return res;
    }
}
