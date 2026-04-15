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
 *    totalRefs            uint32 LE   (4 bytes)  (=0 for v1 canonical P2PKH)
 *    refsHash             bytes       (32 bytes) (=zeros for v1)
 *
 * Plan reference: docs/plans/2026-04-15-feat-hashoutputhashes-preimage-fix-plan.md
 * Oracle reference: scripts/radiant_preimage_oracle.py (port of radiantjs sighash.js)
 *
 * The handlers hand us output bytes as they stream in. We feed one byte at
 * a time through a small FSM (amount → script_len → script) and emit a
 * summary into the hashOutputHashesCtx each time we complete an output.
 */

#define RADIANT_CANONICAL_P2PKH_LEN 25
#define RADIANT_MAX_SCRIPT_PUBKEY 10000 /* Generous bound; canonical P2PKH is 25 */

void radiant_output_hash_init(void) {
  if (COIN_KIND != COIN_KIND_RADIANT) {
    return;
  }
  cx_sha256_init_no_throw(&context.hashOutputHashesCtx);
  cx_sha256_init_no_throw(&context.currentOutputScriptCtx);
  context.currentOutputBytesRemaining = 0;
  context.currentOutputSatoshis = 0;
  context.outputParsingSubstate = RADIANT_OUT_AMOUNT;
  /* The amount is accumulated in the low 8 bytes of currentOutputSatoshis;
   * we use currentOutputBytesRemaining to count them down from 8 → 0. */
  context.currentOutputBytesRemaining = 8; /* waiting for 8 bytes of nValue */
}

void radiant_output_hash_reset(void) {
  if (COIN_KIND != COIN_KIND_RADIANT) {
    return;
  }
  /* Security H2 / SpecFlow #4, #6: unconditional reset of all Radiant state
   * including currentOutputScriptCtx (which is re-inited per-output in normal
   * flow, but a cancel mid-script would leave it half-consumed otherwise). */
  cx_sha256_init_no_throw(&context.hashOutputHashesCtx);
  cx_sha256_init_no_throw(&context.currentOutputScriptCtx);
  context.currentOutputBytesRemaining = 0;
  context.currentOutputSatoshis = 0;
  context.outputParsingSubstate = RADIANT_OUT_AMOUNT;
}

unsigned short radiant_output_hash_feed_byte(unsigned char b) {
  if (COIN_KIND != COIN_KIND_RADIANT) {
    return 0;
  }

  switch (context.outputParsingSubstate) {
    case RADIANT_OUT_AMOUNT: {
      /* Accumulate 8 little-endian bytes into currentOutputSatoshis */
      uint8_t byte_index = 8 - (uint8_t)context.currentOutputBytesRemaining;
      context.currentOutputSatoshis |= ((uint64_t)b) << (8 * byte_index);
      context.currentOutputBytesRemaining--;
      if (context.currentOutputBytesRemaining == 0) {
        /* Amount complete. Next: script length varint. */
        context.outputParsingSubstate = RADIANT_OUT_SCRIPT_LEN;
        /* Reuse currentOutputBytesRemaining as "varint bytes seen so far"
         * in the SCRIPT_LEN state (0 = first byte, which is the varint prefix). */
        context.currentOutputBytesRemaining = 0;
      }
      return 0;
    }

    case RADIANT_OUT_SCRIPT_LEN: {
      /* Minimal varint decoder. For canonical P2PKH we expect 0x19 (25) as a
       * single byte. Reject everything else outright: this is v1's "canonical
       * P2PKH enforcement" from the plan (Security/Architecture review). */
      if (context.currentOutputBytesRemaining == 0 && b == RADIANT_CANONICAL_P2PKH_LEN) {
        /* Single-byte varint == 25. Transition to script streaming. */
        cx_sha256_init_no_throw(&context.currentOutputScriptCtx);
        context.currentOutputBytesRemaining = RADIANT_CANONICAL_P2PKH_LEN;
        context.outputParsingSubstate = RADIANT_OUT_SCRIPT;
        return 0;
      }
      /* Anything else — varint prefix, length != 25, etc. — reject.
       * This enforces the v1 "canonical P2PKH only" rule at the device. */
      PRINTF("Radiant: non-canonical-P2PKH output rejected (script_len byte 0x%02x)\n", b);
      return SW_INCORRECT_DATA;
    }

    case RADIANT_OUT_SCRIPT: {
      /* Stream the scriptPubKey bytes into the per-output inner sha256 */
      if (cx_hash_no_throw(&context.currentOutputScriptCtx.header, 0, &b, 1, NULL, 0)) {
        return SW_TECHNICAL_PROBLEM;
      }
      context.currentOutputBytesRemaining--;
      if (context.currentOutputBytesRemaining == 0) {
        /* Output complete. Finalize double-SHA256 of scriptPubKey, emit the
         * 76-byte summary into hashOutputHashesCtx. */
        uint8_t digest1[32];
        if (cx_hash_no_throw(&context.currentOutputScriptCtx.header, CX_LAST,
                             NULL, 0, digest1, 32)) {
          return SW_TECHNICAL_PROBLEM;
        }
        cx_sha256_t finalCtx;
        cx_sha256_init_no_throw(&finalCtx);
        uint8_t scriptHash[32]; /* sha256d(scriptPubKey) */
        if (cx_hash_no_throw(&finalCtx.header, CX_LAST, digest1, 32, scriptHash, 32)) {
          return SW_TECHNICAL_PROBLEM;
        }

        /* Emit per-output summary: nValue(8 LE) | scriptHash(32) | totalRefs=0(4 LE) | refsHash=zeros(32) */
        uint8_t summary[76];
        for (int i = 0; i < 8; i++) {
          summary[i] = (context.currentOutputSatoshis >> (8 * i)) & 0xff;
        }
        memmove(summary + 8, scriptHash, 32);
        /* totalRefs = 0 (4 bytes LE) */
        summary[40] = 0;
        summary[41] = 0;
        summary[42] = 0;
        summary[43] = 0;
        /* refsHash = 32 zero bytes */
        memset(summary + 44, 0, 32);

        if (cx_hash_no_throw(&context.hashOutputHashesCtx.header, 0,
                             summary, sizeof(summary), NULL, 0)) {
          return SW_TECHNICAL_PROBLEM;
        }

        /* Prepare for the next output */
        context.outputParsingSubstate = RADIANT_OUT_AMOUNT;
        context.currentOutputBytesRemaining = 8;
        context.currentOutputSatoshis = 0;
      }
      return 0;
    }

    default:
      /* Defensive: should never happen */
      PRINTF("Radiant: invalid outputParsingSubstate %d\n", context.outputParsingSubstate);
      return SW_TECHNICAL_PROBLEM;
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
