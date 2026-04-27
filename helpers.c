/*******************************************************************************
 *   Ledger App - Bitcoin Wallet
 *   (c) 2016-2019 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "base58.h"
#include "io.h"
#include "ledger_assert.h"
#include "lib_standard_app/bip32.h"
#include "lib_standard_app/crypto_helpers.h"
#include "read.h"

#include "apdu/apdu_constants.h"
#include "context.h"
#include "helpers.h"

void public_key_hash160(unsigned char *in, unsigned short inlen,
                        unsigned char out[static CX_RIPEMD160_SIZE]) {
  unsigned char buffer[CX_SHA256_SIZE];
  cx_hash_sha256(in, inlen, buffer, sizeof(buffer));
  cx_ripemd160_hash(buffer, sizeof(buffer), out);
}

static void compute_checksum(unsigned char *in, unsigned short inlen,
                             unsigned char output[static 4]) {
  unsigned char checksumBuffer[32];
  cx_hash_sha256(in, inlen, checksumBuffer, 32);
  cx_hash_sha256(checksumBuffer, 32, checksumBuffer, 32);

  PRINTF("Checksum\n%.*H\n", 4, checksumBuffer);
  memmove(output, checksumBuffer, 4);
}

unsigned short public_key_to_encoded_base58(unsigned char *in,
                                            unsigned short inlen,
                                            unsigned char *out,
                                            unsigned short outlen,
                                            unsigned short version,
                                            unsigned char alreadyHashed) {
  unsigned char tmpBuffer[34];

  unsigned char versionSize = (version > 255 ? 2 : 1);
  short outputLen;

  if (!alreadyHashed) {
    PRINTF("To hash\n%.*H\n", inlen, in);
    public_key_hash160(in, inlen, tmpBuffer + versionSize);
    PRINTF("Hash160\n%.*H\n", 20, (tmpBuffer + versionSize));
    if (version > 255) {
      tmpBuffer[0] = (version >> 8);
      tmpBuffer[1] = version;
    } else {
      tmpBuffer[0] = version;
    }
  } else {
    memmove(tmpBuffer, in, 20 + versionSize);
  }

  compute_checksum(tmpBuffer, 20 + versionSize, tmpBuffer + 20 + versionSize);

  outputLen = base58_encode(tmpBuffer, 24 + versionSize, (char *)out, outlen);
  LEDGER_ASSERT(outputLen >= 0, "Error encoding public key");

  return outputLen;
}

void swap_bytes(unsigned char *target, unsigned char *source,
                unsigned char size) {
  unsigned char i;
  for (i = 0; i < size; i++) {
    target[i] = source[size - 1 - i];
  }
}

/*
Checks if the values of a derivation path are within "normal" (arbitrary)
ranges: Account < 100, change == 1 or 0, address index < 50000
Returns 1 if the path is unusual, or not compliant with BIP44*/
unsigned char bip44_derivation_guard(const unsigned char *bip32Path,
                                     bool is_change_path) {
  unsigned char path_len;
  bip32_path_t bip32PathInt;

  path_len = bip32Path[0];
  if (!parse_serialized_path(&bip32PathInt, bip32Path, MAX_BIP32_PATH_LENGTH)) {
    return 1;
  }

  // If the path length is not compliant with BIP44 or if the purpose don't
  // match regular usage, return a warning
  if (path_len != BIP44_PATH_LEN ||
      ((bip32PathInt.path[BIP44_PURPOSE_OFFSET] ^ 0x80000000) != 44 &&
       (bip32PathInt.path[BIP44_PURPOSE_OFFSET] ^ 0x80000000) != 49 &&
       (bip32PathInt.path[BIP44_PURPOSE_OFFSET] ^ 0x80000000) != 84)) {
    return 1;
  }

  // If the coin type doesn't match, return a warning
  if ((BIP44_COIN_TYPE != 0) && (((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET] ^
                                   0x80000000) != BIP44_COIN_TYPE) &&
                                 ((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET] ^
                                   0x80000000) != BIP44_COIN_TYPE_2))) {
    return 1;
  }

  // If the account or address index is very high or if the change isn't 1,
  // return a warning
  if ((bip32PathInt.path[BIP44_ACCOUNT_OFFSET] ^ 0x80000000) >
                  MAX_BIP44_ACCOUNT_RECOMMENDED ||
              bip32PathInt.path[BIP44_CHANGE_OFFSET] != is_change_path
          ? 1
          : 0 || bip32PathInt.path[BIP44_ADDRESS_INDEX_OFFSET] >
                     MAX_BIP44_ADDRESS_INDEX_RECOMMENDED) {
    return 1;
  }

  return 0;
}

/*
Only enforce the structure or coin type for consumed UTXOs or a public address
Returns 0 if the path is non compliant, or 1 if compliant
*/
unsigned char enforce_bip44_coin_type(const unsigned char *bip32Path,
                                      bool for_pubkey) {
  bip32_path_t bip32PathInt;
  // No enforcement required
  if (BIP44_COIN_TYPE == 0) {
    return 1;
  }
  // Path is too short - always require a user validation if signing
  if (bip32Path[0] < 2) {
    return for_pubkey;
  }

  if (!parse_serialized_path(&bip32PathInt, bip32Path, MAX_BIP32_PATH_LENGTH)) {
    return 1;
  }

  // Path is not compliant with BIP 44 or derivatives - valid if not signing
  if (!(((bip32PathInt.path[BIP44_PURPOSE_OFFSET] ^ 0x80000000) == 44 ||
         (bip32PathInt.path[BIP44_PURPOSE_OFFSET] ^ 0x80000000) == 49 ||
         (bip32PathInt.path[BIP44_PURPOSE_OFFSET] ^ 0x80000000) == 84))) {
    return for_pubkey;
  }

  if (((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET] ^ 0x80000000) ==
       BIP44_COIN_TYPE) ||
      ((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET] ^ 0x80000000) ==
       BIP44_COIN_TYPE_2)) {
    // Valid BIP 44 path
    return 1;
  }
  // Everything else needs a user validation
  return 0;
}

// Strict path-lock for COIN_KIND_RADIANT (no-op for other coins).
// Returns true if the request can proceed; false if the caller must reject.
bool is_radiant_path_allowed(const unsigned char *bip32Path) {
  if (COIN_KIND != COIN_KIND_RADIANT) {
    return true;
  }
  bip32_path_t p;
  if (bip32Path[0] < 2) {
    return false;
  }
  if (!parse_serialized_path(&p, bip32Path, MAX_BIP32_PATH_LENGTH)) {
    return false;
  }
  // Require m/44'/512'/...
  if ((p.path[BIP44_PURPOSE_OFFSET] ^ 0x80000000) != 44) {
    return false;
  }
  if ((p.path[BIP44_COIN_TYPE_OFFSET] ^ 0x80000000) != 512) {
    return false;
  }
  return true;
}

/* ==== Radiant hashOutputHashes streaming helpers ====
 *
 * The preimage Radiant expects includes an extra 32-byte hashOutputHashes
 * field between nSequence and hashOutputs. hashOutputHashes is sha256d of
 * the concatenation of per-output 76-byte summaries:
 *
 *    nValue               uint64 LE   (8 bytes)
 *    sha256d(scriptPubKey) bytes      (32 bytes)
 *    totalRefs            uint32 LE   (4 bytes)
 *    refsHash             bytes       (32 bytes)
 *
 * For Glyph outputs, the opcode walker scans scriptPubKey byte-by-byte to
 * find OP_PUSHINPUTREF (0xD0) and OP_PUSHINPUTREFSINGLETON (0xD8). Each
 * carries a 36-byte ref (32B txid + 4B vout). Unique refs are deduplicated,
 * sorted lexicographically, concatenated, then sha256d'd → refsHash.
 * totalRefs = count of unique push-refs. For plain P2PKH: totalRefs=0,
 * refsHash=zeros (identical to the v1 result).
 *
 * Plan reference: docs/plans/2026-04-15-feat-hashoutputhashes-preimage-fix-plan.md
 * Oracle reference: scripts/radiant_preimage_oracle.py (port of radiantjs sighash.js)
 */

/* Maximum allowed script length. Glyph scripts can be large but we need a
 * bound to protect against pathological cases. 10000 matches Bitcoin's
 * MAX_SCRIPT_SIZE. */
#define RADIANT_MAX_SCRIPT_PUBKEY 10000

/* Reset opcode walker + push-ref accumulator for the next output. */
static void radiant_opcode_walker_init(void) {
  context.opcodeSubstate = RADIANT_OP_NEXT;
  context.opSkipRemaining = 0;
  context.opPushdataLenOffset = 0;
  context.opPushdataLenExpected = 0;
  context.refBufOffset = 0;
  context.numPushRefs = 0;
  context.numDisallowRefs = 0;
}

/* Insert a disallow-ref into the deduplicated accumulator.
 * Mirrors radiant_push_ref_insert but for OP_DISALLOWPUSHINPUTREF. */
static unsigned short radiant_disallow_ref_insert(const uint8_t ref[RADIANT_REF_LEN]) {
  for (uint8_t i = 0; i < context.numDisallowRefs; i++) {
    if (memcmp(context.disallowRefs[i], ref, RADIANT_REF_LEN) == 0) {
      return 0; /* already present */
    }
  }
  if (context.numDisallowRefs >= RADIANT_MAX_PUSH_REFS) {
    PRINTF("Radiant: too many disallow-refs in single output (max %d)\n", RADIANT_MAX_PUSH_REFS);
    return SW_INCORRECT_DATA;
  }
  memmove(context.disallowRefs[context.numDisallowRefs], ref, RADIANT_REF_LEN);
  context.numDisallowRefs++;
  return 0;
}

/* Insert a push-ref into the sorted, deduplicated accumulator.
 * Returns 0 on success, SW code if capacity exceeded. */
static unsigned short radiant_push_ref_insert(const uint8_t ref[RADIANT_REF_LEN]) {
  /* Check for duplicate (linear scan is fine for ≤8 entries). */
  for (uint8_t i = 0; i < context.numPushRefs; i++) {
    if (memcmp(context.pushRefs[i], ref, RADIANT_REF_LEN) == 0) {
      return 0; /* already present */
    }
  }
  if (context.numPushRefs >= RADIANT_MAX_PUSH_REFS) {
    PRINTF("Radiant: too many push-refs in single output (max %d)\n", RADIANT_MAX_PUSH_REFS);
    return SW_INCORRECT_DATA;
  }
  /* Insertion sort: find position, shift, insert. */
  uint8_t pos = context.numPushRefs;
  for (uint8_t i = 0; i < context.numPushRefs; i++) {
    if (memcmp(ref, context.pushRefs[i], RADIANT_REF_LEN) < 0) {
      pos = i;
      break;
    }
  }
  /* Shift entries [pos..numPushRefs-1] right by one. */
  for (uint8_t i = context.numPushRefs; i > pos; i--) {
    memmove(context.pushRefs[i], context.pushRefs[i - 1], RADIANT_REF_LEN);
  }
  memmove(context.pushRefs[pos], ref, RADIANT_REF_LEN);
  context.numPushRefs++;
  return 0;
}

/* Compute (totalRefs, refsHash) from the accumulated push-refs.
 * Writes 4-byte totalRefs LE + 32-byte refsHash into out (must be ≥36 bytes). */
static unsigned short radiant_compute_refs_hash(uint8_t *out) {
  uint32_t n = context.numPushRefs;
  out[0] = (uint8_t)(n & 0xff);
  out[1] = (uint8_t)((n >> 8) & 0xff);
  out[2] = (uint8_t)((n >> 16) & 0xff);
  out[3] = (uint8_t)((n >> 24) & 0xff);

  if (n == 0) {
    memset(out + 4, 0, 32);
    return 0;
  }

  /* sha256d(concat of all sorted unique refs) */
  cx_sha256_t h;
  cx_sha256_init_no_throw(&h);
  for (uint8_t i = 0; i < n; i++) {
    if (cx_hash_no_throw(&h.header, 0, context.pushRefs[i], RADIANT_REF_LEN, NULL, 0)) {
      return SW_TECHNICAL_PROBLEM;
    }
  }
  uint8_t digest1[32];
  if (cx_hash_no_throw(&h.header, CX_LAST, NULL, 0, digest1, 32)) {
    return SW_TECHNICAL_PROBLEM;
  }
  cx_sha256_init_no_throw(&h);
  if (cx_hash_no_throw(&h.header, CX_LAST, digest1, 32, out + 4, 32)) {
    return SW_TECHNICAL_PROBLEM;
  }
  return 0;
}

/* Feed one script byte through the opcode walker. Extracts push-refs.
 * Returns 0 on success, non-zero SW on error. */
static unsigned short radiant_opcode_feed_byte(unsigned char b) {
  switch (context.opcodeSubstate) {
    case RADIANT_OP_NEXT: {
      /* Reading the next opcode.
       *
       * Bounds policy: currentOutputBytesRemaining includes the current byte
       * at entry (decrement happens after this function returns). For any
       * opcode that consumes K following bytes, we require
       *   currentOutputBytesRemaining > K
       * (strict) so that after the outer decrement, K more bytes are still
       * available. Prevents PUSHDATA* integer-wrap and truncated-ref cases
       * flagged by the 2026-04-16 security audit. */
      if (b > 0 && b < OP_PUSHDATA1) {
        /* Direct push: skip next `b` bytes */
        if ((uint32_t)b >= context.currentOutputBytesRemaining) {
          PRINTF("Radiant: direct-push length %u overshoots script end\n", b);
          return SW_INCORRECT_DATA;
        }
        context.opSkipRemaining = b;
        context.opcodeSubstate = RADIANT_OP_SKIP_DATA;
      } else if (b == OP_PUSHDATA1) {
        if (context.currentOutputBytesRemaining <= 1) return SW_INCORRECT_DATA;
        context.opPushdataLenExpected = 1;
        context.opPushdataLenOffset = 0;
        context.opcodeSubstate = RADIANT_OP_PUSHDATA_LEN;
      } else if (b == OP_PUSHDATA2) {
        if (context.currentOutputBytesRemaining <= 2) return SW_INCORRECT_DATA;
        context.opPushdataLenExpected = 2;
        context.opPushdataLenOffset = 0;
        context.opcodeSubstate = RADIANT_OP_PUSHDATA_LEN;
      } else if (b == OP_PUSHDATA4) {
        if (context.currentOutputBytesRemaining <= 4) return SW_INCORRECT_DATA;
        context.opPushdataLenExpected = 4;
        context.opPushdataLenOffset = 0;
        context.opcodeSubstate = RADIANT_OP_PUSHDATA_LEN;
      } else if (b == OP_PUSHINPUTREF || b == OP_REQUIREINPUTREF ||
                 b == OP_DISALLOWPUSHINPUTREF || b == OP_DISALLOWPUSHINPUTREFSIBLING ||
                 b == OP_PUSHINPUTREFSINGLETON) {
        /* Need exactly RADIANT_REF_LEN (36) more bytes after this opcode. */
        if (context.currentOutputBytesRemaining <= RADIANT_REF_LEN) {
          PRINTF("Radiant: push-ref opcode 0x%02x but only %u bytes remain\n",
                 b, (unsigned)context.currentOutputBytesRemaining);
          return SW_INCORRECT_DATA;
        }
        context.opCurrentRefOpcode = b;
        context.refBufOffset = 0;
        context.opcodeSubstate = RADIANT_OP_READ_REF;
      }
      /* All other opcodes (OP_0, OP_1..OP_16, OP_DUP, etc.) are 1-byte, no payload. */
      return 0;
    }

    case RADIANT_OP_SKIP_DATA: {
      context.opSkipRemaining--;
      if (context.opSkipRemaining == 0) {
        context.opcodeSubstate = RADIANT_OP_NEXT;
      }
      return 0;
    }

    case RADIANT_OP_PUSHDATA_LEN: {
      context.opPushdataLenBuf[context.opPushdataLenOffset++] = b;
      if (context.opPushdataLenOffset >= context.opPushdataLenExpected) {
        uint32_t len = 0;
        for (uint8_t i = 0; i < context.opPushdataLenExpected; i++) {
          len |= ((uint32_t)context.opPushdataLenBuf[i]) << (8 * i);
        }
        /* Bound: after the outer decrement for this final length byte,
         * len bytes must still be available. Prevents PUSHDATA4 integer-wrap
         * where len claims 4GB but few bytes remain. */
        if (len >= context.currentOutputBytesRemaining) {
          PRINTF("Radiant: PUSHDATA length %u overshoots %u remaining\n",
                 (unsigned)len, (unsigned)context.currentOutputBytesRemaining);
          return SW_INCORRECT_DATA;
        }
        if (len > 0) {
          context.opSkipRemaining = len;
          context.opcodeSubstate = RADIANT_OP_SKIP_DATA;
        } else {
          context.opcodeSubstate = RADIANT_OP_NEXT;
        }
      }
      return 0;
    }

    case RADIANT_OP_READ_REF: {
      context.refBuf[context.refBufOffset++] = b;
      if (context.refBufOffset >= RADIANT_REF_LEN) {
        /* Full ref read. Route by opcode:
         *   PUSHINPUTREF / PUSHINPUTREFSINGLETON → pushRefs (contributes to refsHash)
         *   DISALLOWPUSHINPUTREF                  → disallowRefs (conflict check at emit)
         *   REQUIREINPUTREF / DISALLOWPUSHINPUTREFSIBLING → no accumulator (ignored per radiantjs) */
        if (context.opCurrentRefOpcode == OP_PUSHINPUTREF ||
            context.opCurrentRefOpcode == OP_PUSHINPUTREFSINGLETON) {
          unsigned short sw = radiant_push_ref_insert(context.refBuf);
          if (sw) return sw;
        } else if (context.opCurrentRefOpcode == OP_DISALLOWPUSHINPUTREF) {
          unsigned short sw = radiant_disallow_ref_insert(context.refBuf);
          if (sw) return sw;
        }
        context.opcodeSubstate = RADIANT_OP_NEXT;
      }
      return 0;
    }

    default:
      return SW_TECHNICAL_PROBLEM;
  }
}

void radiant_output_hash_init(void) {
  if (COIN_KIND != COIN_KIND_RADIANT) {
    return;
  }
  cx_sha256_init_no_throw(&context.hashOutputHashesCtx);
  cx_sha256_init_no_throw(&context.currentOutputScriptCtx);
  context.currentOutputBytesRemaining = 8; /* waiting for 8 bytes of nValue */
  context.currentOutputSatoshis = 0;
  context.currentOutputScriptLen = 0;
  context.outputParsingSubstate = RADIANT_OUT_AMOUNT;
  context.varintBufOffset = 0;
  context.varintBufExpected = 0;
  radiant_opcode_walker_init();
}

void radiant_output_hash_reset(void) {
  if (COIN_KIND != COIN_KIND_RADIANT) {
    return;
  }
  cx_sha256_init_no_throw(&context.hashOutputHashesCtx);
  cx_sha256_init_no_throw(&context.currentOutputScriptCtx);
  context.currentOutputBytesRemaining = 0;
  context.currentOutputSatoshis = 0;
  context.currentOutputScriptLen = 0;
  context.outputParsingSubstate = RADIANT_OUT_AMOUNT;
  context.varintBufOffset = 0;
  context.varintBufExpected = 0;
  radiant_opcode_walker_init();
}

unsigned short radiant_output_hash_feed_byte(unsigned char b) {
  if (COIN_KIND != COIN_KIND_RADIANT) {
    return 0;
  }

  switch (context.outputParsingSubstate) {
    case RADIANT_OUT_AMOUNT: {
      uint8_t byte_index = 8 - (uint8_t)context.currentOutputBytesRemaining;
      context.currentOutputSatoshis |= ((uint64_t)b) << (8 * byte_index);
      context.currentOutputBytesRemaining--;
      if (context.currentOutputBytesRemaining == 0) {
        context.outputParsingSubstate = RADIANT_OUT_SCRIPT_LEN;
        context.varintBufOffset = 0;
        context.varintBufExpected = 0;
      }
      return 0;
    }

    case RADIANT_OUT_SCRIPT_LEN: {
      /* Bitcoin compact-size varint decoder.
       * First byte: <0xFD → value is the byte itself
       *             0xFD  → next 2 bytes (LE)
       *             0xFE  → next 4 bytes (LE)
       *             0xFF  → next 8 bytes (LE) — reject, scripts can't be that long */
      if (context.varintBufExpected == 0) {
        /* First byte of varint */
        if (b < 0xFD) {
          context.currentOutputScriptLen = b;
        } else if (b == 0xFD) {
          context.varintBufExpected = 2;
          context.varintBufOffset = 0;
          return 0;
        } else if (b == 0xFE) {
          context.varintBufExpected = 4;
          context.varintBufOffset = 0;
          return 0;
        } else {
          PRINTF("Radiant: 8-byte varint not supported for script length\n");
          return SW_INCORRECT_DATA;
        }
      } else {
        /* Multi-byte varint continuation */
        context.varintBuf[context.varintBufOffset++] = b;
        if (context.varintBufOffset < context.varintBufExpected) {
          return 0;
        }
        /* Decode LE bytes */
        context.currentOutputScriptLen = 0;
        for (uint8_t i = 0; i < context.varintBufExpected; i++) {
          context.currentOutputScriptLen |= ((uint32_t)context.varintBuf[i]) << (8 * i);
        }
      }

      /* Script length now decoded. Sanity bound. */
      if (context.currentOutputScriptLen > RADIANT_MAX_SCRIPT_PUBKEY) {
        PRINTF("Radiant: script too long (%u)\n", (unsigned)context.currentOutputScriptLen);
        return SW_INCORRECT_DATA;
      }

      /* OP_RETURN (script_len > 0, first byte 0x6a) and zero-length scripts
       * are fine — the opcode walker just won't find any push-refs. */
      cx_sha256_init_no_throw(&context.currentOutputScriptCtx);
      context.currentOutputBytesRemaining = context.currentOutputScriptLen;
      radiant_opcode_walker_init();
      context.outputParsingSubstate = RADIANT_OUT_SCRIPT;

      /* Handle zero-length scripts (degenerate edge case). */
      if (context.currentOutputScriptLen == 0) {
        goto emit_summary;
      }
      return 0;
    }

    case RADIANT_OUT_SCRIPT: {
      /* Feed byte into both the script hash and the opcode walker. */
      if (cx_hash_no_throw(&context.currentOutputScriptCtx.header, 0, &b, 1, NULL, 0)) {
        return SW_TECHNICAL_PROBLEM;
      }
      unsigned short sw = radiant_opcode_feed_byte(b);
      if (sw) return sw;

      context.currentOutputBytesRemaining--;
      if (context.currentOutputBytesRemaining == 0) {
        goto emit_summary;
      }
      return 0;
    }

    default:
      PRINTF("Radiant: invalid outputParsingSubstate %d\n", context.outputParsingSubstate);
      return SW_TECHNICAL_PROBLEM;
  }

emit_summary: {
    /* Consensus conflict check: radiantjs rejects any output where a ref
     * appears in both push-ref and disallow-ref sets. Mainnet would reject
     * the signed tx anyway, but catching it here keeps device-vs-oracle
     * agreement and surfaces a clear error before signing. */
    for (uint8_t i = 0; i < context.numDisallowRefs; i++) {
      for (uint8_t j = 0; j < context.numPushRefs; j++) {
        if (memcmp(context.disallowRefs[i], context.pushRefs[j], RADIANT_REF_LEN) == 0) {
          PRINTF("Radiant: disallow-ref conflict with push-ref in same output\n");
          return SW_INCORRECT_DATA;
        }
      }
    }

    /* Output complete. Finalize sha256d(scriptPubKey). */
    uint8_t digest1[32];
    if (cx_hash_no_throw(&context.currentOutputScriptCtx.header, CX_LAST,
                         NULL, 0, digest1, 32)) {
      return SW_TECHNICAL_PROBLEM;
    }
    cx_sha256_t finalCtx;
    cx_sha256_init_no_throw(&finalCtx);
    uint8_t scriptHash[32];
    if (cx_hash_no_throw(&finalCtx.header, CX_LAST, digest1, 32, scriptHash, 32)) {
      return SW_TECHNICAL_PROBLEM;
    }

    /* Build 76-byte per-output summary:
     * nValue(8 LE) | sha256d(scriptPubKey)(32) | totalRefs(4 LE) | refsHash(32) */
    uint8_t summary[76];
    for (int i = 0; i < 8; i++) {
      summary[i] = (context.currentOutputSatoshis >> (8 * i)) & 0xff;
    }
    memmove(summary + 8, scriptHash, 32);

    unsigned short emit_sw = radiant_compute_refs_hash(summary + 40);
    if (emit_sw) return emit_sw;

    if (cx_hash_no_throw(&context.hashOutputHashesCtx.header, 0,
                         summary, sizeof(summary), NULL, 0)) {
      return SW_TECHNICAL_PROBLEM;
    }

    /* Prepare for the next output */
    context.outputParsingSubstate = RADIANT_OUT_AMOUNT;
    context.currentOutputBytesRemaining = 8;
    context.currentOutputSatoshis = 0;
    return 0;
  }
}

unsigned short radiant_output_hash_finalize(void) {
  /* Entry-point assertion (one, not per-write). If this fires, a future
   * refactor accidentally routed a non-Radiant build through this path. */
  if (COIN_KIND != COIN_KIND_RADIANT) {
    return SW_TECHNICAL_PROBLEM;
  }
  /* Double-SHA256 of the accumulated per-output summaries. */
  uint8_t digest1[32];
  if (cx_hash_no_throw(&context.hashOutputHashesCtx.header, CX_LAST,
                       NULL, 0, digest1, 32)) {
    return SW_TECHNICAL_PROBLEM;
  }
  cx_sha256_t finalCtx;
  cx_sha256_init_no_throw(&finalCtx);
  if (cx_hash_no_throw(&finalCtx.header, CX_LAST, digest1, 32,
                       context.segwit.cache.hashedOutputHashes, 32)) {
    return SW_TECHNICAL_PROBLEM;
  }
  PRINTF("RADIANT hashedOutputHashes\n%.*H\n", 32, context.segwit.cache.hashedOutputHashes);
  return 0;
}

int sign_finalhash(unsigned char *path, size_t path_len, unsigned char *in,
                   unsigned short inlen, unsigned char *out, size_t *outlen) {

  unsigned int info = 0;

  io_seproxyhal_io_heartbeat();

  bip32_path_t bip32Path;
  bip32Path.length = path[0];

  if (!parse_serialized_path(&bip32Path, path, path_len)) {
    return -1;
  }

  if (bip32_derive_ecdsa_sign_hash_256(CX_CURVE_SECP256K1, bip32Path.path,
                                       bip32Path.length,
                                       CX_LAST | CX_RND_RFC6979, CX_SHA256, in,
                                       inlen, out, outlen, &info) != CX_OK) {
    return -1;
  }

  // Store information about the parity of the 'y' coordinate
  if (info & CX_ECCINFO_PARITY_ODD) {
    out[0] |= 0x01;
  }

  io_seproxyhal_io_heartbeat();
  return 0;
}

int get_public_key(const unsigned char *keyPath, size_t keyPath_len,
                   uint8_t raw_pubkey[static 65], unsigned char *chainCode) {

  bip32_path_t bip32Path;

  if (!parse_serialized_path(&bip32Path, keyPath, keyPath_len)) {
    return -1;
  }

  if (bip32_derive_get_pubkey_256(CX_CURVE_SECP256K1, bip32Path.path,
                                  bip32Path.length, raw_pubkey, chainCode,
                                  CX_SHA512) != CX_OK) {
    return -1;
  }

  return 0;
}

void compress_public_key_value(unsigned char *value) {
  bool odd = (value[64] & 1);
  value[0] = odd ? 0x03 : 0x02;
}

bool parse_serialized_path(bip32_path_t *path,
                           const unsigned char *serialized_path,
                           unsigned char serialized_path_length) {
  if (serialized_path_length < 1 || serialized_path[0] > MAX_BIP32_PATH ||
      serialized_path[0] * 4 + 1 > serialized_path_length)
    return false;
  path->length = serialized_path[0];
  serialized_path++;
  for (int i = 0; i < path->length; i += 1, serialized_path += 4) {
    path->path[i] = read_u32_be(serialized_path, 0);
  }
  return true;
}
