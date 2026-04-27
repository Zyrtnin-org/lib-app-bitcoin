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

#pragma once

#include "cx.h"
#include "filesystem_tx.h"
#include "os.h"
#include "stdbool.h"

#define OUTPUT_SCRIPT_REGULAR_PRE_LENGTH 4
#define OUTPUT_SCRIPT_REGULAR_POST_LENGTH 2
#define OUTPUT_SCRIPT_P2SH_PRE_LENGTH 3
#define OUTPUT_SCRIPT_P2SH_POST_LENGTH 1

#define OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET 3

typedef struct bip32_path {
  unsigned char length;
  unsigned int path[MAX_BIP32_PATH];
} bip32_path_t;

void public_key_hash160(unsigned char *in, unsigned short inlen,
                        unsigned char out[static CX_RIPEMD160_SIZE]);
unsigned short public_key_to_encoded_base58(
    unsigned char *in, unsigned short inlen, unsigned char *out,
    unsigned short outlen, unsigned short version, unsigned char alreadyHashed);

unsigned char bip44_derivation_guard(const unsigned char *bip32Path,
                                     bool is_change_path);
unsigned char enforce_bip44_coin_type(const unsigned char *bip32Path,
                                      bool for_pubkey);

// Strict path-lock for COIN_KIND_RADIANT only (no-op for other coins).
// Returns true if the path is acceptable for Radiant (under m/44'/512'/...),
// false if it must be rejected outright with SW_INCORRECT_DATA.
// Defense-in-depth: LSB-014 install-time enforcement was empirically not active
// on current Nano S Plus firmware (Phase 0 Task 0.0, 2026-04-15) — this runtime
// check is the actual line of defense.
bool is_radiant_path_allowed(const unsigned char *bip32Path);

/* Radiant-only output-streaming helpers. No-op for other COIN_KINDs.
 *
 * The device streams tx outputs in as multiple APDU chunks. For each output,
 * we need to (a) pass bytes through the existing hashedOutputs stream, and
 * (b) ALSO compute a per-output summary that feeds into hashOutputHashes.
 *
 * The summary is 76 bytes: nValue(8) + sha256d(scriptPubKey)(32) + totalRefs(4) + refsHash(32).
 *
 * The opcode walker scans each script for Glyph push-ref opcodes (0xD0, 0xD8),
 * extracts their 36-byte ref payloads, deduplicates and sorts them, then computes
 * refsHash = sha256d(concat of sorted unique refs). For plain P2PKH (no refs),
 * totalRefs=0 and refsHash=zeros — same result as the v1 implementation.
 *
 * These helpers are called from the output parsing loop in
 * handler/hash_input_finalize_full.c, which hands them output bytes as they
 * arrive. The byte stream format is <amount(8 LE)> <varint script_len> <script_bytes>.
 */

/* Initialize the running hashOutputHashes accumulator. Called once at the
 * start of an output-hashing pass (currently invoked from hash_input_start.c
 * when COIN_KIND == COIN_KIND_RADIANT). */
void radiant_output_hash_init(void);

/* Feed one byte of the output stream to the Radiant per-output FSM.
 * Advances the FSM across nValue → script_len → script states, and when
 * a full output has been seen emits its 76-byte summary into the running
 * hashOutputHashes context. The script state runs an opcode walker that
 * extracts Glyph push-refs for the refsHash computation.
 *
 * Returns 0 on success, non-zero SW code if the output is rejected
 * (e.g., script exceeds MAX_SCRIPT_PUBKEY, too many push-refs, etc.).
 * The caller must bail out with that SW on reject.
 */
unsigned short radiant_output_hash_feed_byte(unsigned char b);

/* Finalize the running hashOutputHashes accumulator into
 * context.segwit.cache.hashedOutputHashes. One entry-point assertion
 * (`COIN_KIND == COIN_KIND_RADIANT`) guards this; not per-write. Returns 0
 * on success, non-zero SW code otherwise. */
unsigned short radiant_output_hash_finalize(void);

/* Reset all Radiant per-output hashing state. Called from
 * hash_input_finalize_full_reset to ensure clean slate between signs
 * (Security H2: cancel/interrupt safety). No-op for other coins. */
void radiant_output_hash_reset(void);

void swap_bytes(unsigned char *target, unsigned char *source,
                unsigned char size);

int sign_finalhash(unsigned char *path, size_t path_len, unsigned char *in,
                   unsigned short inlen, unsigned char *out, size_t *outlen);

int get_public_key(const unsigned char *keyPath, size_t keyPath_len,
                   uint8_t raw_pubkey[static 65], unsigned char *chainCode);

void compress_public_key_value(unsigned char *value);

bool parse_serialized_path(bip32_path_t *path,
                           const unsigned char *serialized_path,
                           unsigned char serialized_path_length);
