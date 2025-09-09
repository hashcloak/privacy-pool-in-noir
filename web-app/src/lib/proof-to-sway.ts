// Parse Aztec/UltraHonk proof bytes into SwayVerifier.ProofInput

import { G1ProofPointInput, ProofInput } from '@/sway-contracts-api/contracts/SwayVerifier';
import type { BigNumberish } from 'fuels';

const PAIRING_POINTS_SIZE = 16;
const CONST_PROOF_SIZE_LOG_N = 28;
const BATCHED_RELATION_PARTIAL_LEN = 8;
const NUMBER_OF_ENTITIES = 40;
const GEMINI_FOLD_COMMS_LEN = CONST_PROOF_SIZE_LOG_N - 1; // 27

function to32ByteHex(u8: Uint8Array): string {
  if (u8.length !== 32) {
    const out = new Uint8Array(32);
    out.set(u8, 32 - u8.length);
    u8 = out;
  }

  let hex = '0x';
  for (let i = 0; i < 32; i++) hex += u8[i].toString(16).padStart(2, '0');
  return hex;
}

function chunkU256Words(bytes: Uint8Array): string[] {
  if (bytes.length % 32 !== 0) {
    throw new Error(`Proof length ${bytes.length} is not a multiple of 32 bytes.`);
  }
  const words: string[] = [];
  for (let i = 0; i < bytes.length; i += 32) {
    words.push(to32ByteHex(bytes.subarray(i, i + 32)));
  }
  return words;
}

function g1(words: string[], i: number): G1ProofPointInput {
  return {
    x: [words[i], words[i + 1]],
    y: [words[i + 2], words[i + 3]],
  };
}

function expectLen<T>(arr: T[], n: number, name: string) {
  if (arr.length !== n) throw new Error(`${name} length=${arr.length}, expected ${n}`);
}

export function parseAztecProofToSway(proofBytes: Uint8Array): ProofInput {
  const w = chunkU256Words(proofBytes);
  let i = 0;

  const pairing_point_object =
    w.slice(i, i + PAIRING_POINTS_SIZE) as unknown as ProofInput['pairing_point_object'];
  i += PAIRING_POINTS_SIZE;

  const w1 = g1(w, i); i += 4;
  const w2 = g1(w, i); i += 4;
  const w3 = g1(w, i); i += 4;

  const lookup_read_counts = g1(w, i); i += 4;
  const lookup_read_tags   = g1(w, i); i += 4;
  const w4                 = g1(w, i); i += 4;
  const lookup_inverses    = g1(w, i); i += 4;
  const z_perm             = g1(w, i); i += 4;

  // sumcheck_univariates: 28 * (8 u256)
  const scuDynamic: BigNumberish[][] = Array.from({ length: CONST_PROOF_SIZE_LOG_N }, (_, j) =>
    w.slice(
      i + j * BATCHED_RELATION_PARTIAL_LEN,
      i + (j + 1) * BATCHED_RELATION_PARTIAL_LEN
    )
  );
  expectLen(scuDynamic, 28, 'sumcheck_univariates');
  scuDynamic.forEach((row, idx) => expectLen(row, 8, `sumcheck_univariates[${idx}]`));
  const sumcheck_univariates = scuDynamic as unknown as ProofInput['sumcheck_univariates'];
  i += CONST_PROOF_SIZE_LOG_N * BATCHED_RELATION_PARTIAL_LEN;

  // sumcheck_evaluations: 40 u256
  const sceDynamic = w.slice(i, i + NUMBER_OF_ENTITIES);
  expectLen(sceDynamic, 40, 'sumcheck_evaluations');
  const sumcheck_evaluations = sceDynamic as unknown as ProofInput['sumcheck_evaluations'];
  i += NUMBER_OF_ENTITIES;

  // gemini_fold_comms: 27 * G1
  const gfcDynamic: G1ProofPointInput[] = Array.from({ length: GEMINI_FOLD_COMMS_LEN }, (_, j) =>
    g1(w, i + j * 4)
  );
  expectLen(gfcDynamic, 27, 'gemini_fold_comms');
  const gemini_fold_comms = gfcDynamic as unknown as ProofInput['gemini_fold_comms'];
  i += GEMINI_FOLD_COMMS_LEN * 4;

  // gemini_a_evaluations: 28 u256
  const gaeDynamic = w.slice(i, i + CONST_PROOF_SIZE_LOG_N);
  expectLen(gaeDynamic, 28, 'gemini_a_evaluations');
  const gemini_a_evaluations = gaeDynamic as unknown as ProofInput['gemini_a_evaluations'];
  i += CONST_PROOF_SIZE_LOG_N;

  const shplonk_q    = g1(w, i); i += 4;
  const kzg_quotient = g1(w, i); i += 4;

  return {
    pairing_point_object,
    w1, w2, w3, w4,
    z_perm,
    lookup_read_counts,
    lookup_read_tags,
    lookup_inverses,
    sumcheck_univariates,
    sumcheck_evaluations,
    gemini_fold_comms,
    gemini_a_evaluations,
    shplonk_q,
    kzg_quotient,
  };
}

// public_inputs must be [u256; 4] for privacy pool circuit
export function normalizePublicInputs(publicInputs: string[]): ProofInput extends never ? never :
  [BigNumberish, BigNumberish, BigNumberish, BigNumberish] {
  if (publicInputs.length !== 4) {
    throw new Error(`Sway verifier expects exactly 4 public inputs, got ${publicInputs.length}`);
  }
  const toU256Hex = (h: string) => `0x${(h.startsWith('0x') ? h.slice(2) : h).padStart(64, '0')}`;
  return [
    toU256Hex(publicInputs[0]),
    toU256Hex(publicInputs[1]),
    toU256Hex(publicInputs[2]),
    toU256Hex(publicInputs[3]),
  ];
}