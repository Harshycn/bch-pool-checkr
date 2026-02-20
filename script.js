// ═══════════════════════════════════════════════════════════════════════════
//  BCH Stratum Mining.Notify Parser
//  Ported from bch_stratum_inspector.py — pure client-side BCH support
// ═══════════════════════════════════════════════════════════════════════════

// ── Base58 Encoding (Legacy addresses: 1.../3...) ────────────────────────

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(buffer) {
    let num = BigInt('0x' + Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join(''));
    let encoded = '';

    while (num > 0n) {
        const remainder = num % 58n;
        num = num / 58n;
        encoded = BASE58_ALPHABET[Number(remainder)] + encoded;
    }

    // Add leading '1's for leading zero bytes
    for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
        encoded = '1' + encoded;
    }

    return encoded;
}

function sha256(hex) {
    const buffer = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    return crypto.subtle.digest('SHA-256', buffer).then(hash => {
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    });
}

async function doubleSha256(hex) {
    const first = await sha256(hex);
    return sha256(first);
}

async function pubkeyHashToLegacyAddress(hash, version) {
    const versionedHash = version.toString(16).padStart(2, '0') + hash;
    const checksum = (await doubleSha256(versionedHash)).substring(0, 8);
    const fullHash = versionedHash + checksum;
    const bytes = new Uint8Array(fullHash.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    return base58Encode(bytes);
}

// ── CashAddr Encoding (bitcoincash:q.../p...) ────────────────────────────

const CASHADDR_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function cashAddrPolymod(values) {
    const GEN = [
        0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n,
        0xae2eabe2a8n, 0x1e4f43e470n
    ];
    let c = 1n;
    for (const d of values) {
        const c0 = c >> 35n;
        c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
        for (let i = 0; i < 5; i++) {
            if ((c0 >> BigInt(i)) & 1n) {
                c ^= GEN[i];
            }
        }
    }
    return c ^ 1n;
}

function cashAddrHrpExpand(prefix) {
    const ret = [];
    for (let i = 0; i < prefix.length; i++) {
        ret.push(prefix.charCodeAt(i) & 0x1f);
    }
    ret.push(0);
    return ret;
}

function convertBits(data, fromBits, toBits, pad = true) {
    let acc = 0;
    let bits = 0;
    const ret = [];
    const maxv = (1 << toBits) - 1;

    for (const value of data) {
        acc = (acc << fromBits) | value;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            ret.push((acc >> bits) & maxv);
        }
    }

    if (pad && bits > 0) {
        ret.push((acc << (toBits - bits)) & maxv);
    }

    return ret;
}

function hash160ToCashAddr(hash160Hex, scriptType = 'P2PKH') {
    const prefix = 'bitcoincash';
    const versionByte = scriptType === 'P2PKH' ? 0x00 : 0x08;
    const hash160Bytes = hash160Hex.match(/.{2}/g).map(b => parseInt(b, 16));
    const payload = convertBits([versionByte].concat(hash160Bytes), 8, 5);
    const values = cashAddrHrpExpand(prefix).concat(payload).concat([0, 0, 0, 0, 0, 0, 0, 0]);
    const polymod = cashAddrPolymod(values);
    const checksum = [];
    for (let i = 0; i < 8; i++) {
        checksum.push(Number((polymod >> BigInt(5 * (7 - i))) & 0x1fn));
    }
    return prefix + ':' + payload.concat(checksum).map(d => CASHADDR_CHARSET[d]).join('');
}

// ── RIPEMD-160 (pure JS, for P2PK → address derivation) ─────────────────

function ripemd160(msgBytes) {
    const KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
    const KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];
    const RL = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
    const RR = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
    const SL = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
    const SR = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];

    function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
    function f(j, x, y, z) {
        if (j < 16) return (x ^ y ^ z) >>> 0;
        if (j < 32) return ((x & y) | (~x & z)) >>> 0;
        if (j < 48) return ((x | ~y) ^ z) >>> 0;
        if (j < 64) return ((x & z) | (y & ~z)) >>> 0;
        return (x ^ (y | ~z)) >>> 0;
    }

    const len = msgBytes.length;
    const bitLen = len * 8;
    const padded = new Uint8Array(((len + 9 + 63) & ~63));
    padded.set(msgBytes);
    padded[len] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, bitLen >>> 0, true);
    view.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true);

    let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;

    for (let offset = 0; offset < padded.length; offset += 64) {
        const X = [];
        for (let i = 0; i < 16; i++) {
            X.push(view.getUint32(offset + i * 4, true));
        }

        let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
        let ar = h0, br = h1, cr = h2, dr = h3, er = h4;

        for (let j = 0; j < 80; j++) {
            const jDiv = Math.floor(j / 16);
            let t = (al + f(j, bl, cl, dl) + X[RL[j]] + KL[jDiv]) >>> 0;
            t = (rotl(t, SL[j]) + el) >>> 0;
            al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;

            t = (ar + f(79 - j, br, cr, dr) + X[RR[j]] + KR[jDiv]) >>> 0;
            t = (rotl(t, SR[j]) + er) >>> 0;
            ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
        }

        const t = (h1 + cl + dr) >>> 0;
        h1 = (h2 + dl + er) >>> 0;
        h2 = (h3 + el + ar) >>> 0;
        h3 = (h4 + al + br) >>> 0;
        h4 = (h0 + bl + cr) >>> 0;
        h0 = t;
    }

    const out = new Uint8Array(20);
    const ov = new DataView(out.buffer);
    ov.setUint32(0, h0, true); ov.setUint32(4, h1, true); ov.setUint32(8, h2, true);
    ov.setUint32(12, h3, true); ov.setUint32(16, h4, true);
    return out;
}

async function hash160(pubkeyHex) {
    const sha = await sha256(pubkeyHex);
    const shaBytes = new Uint8Array(sha.match(/.{2}/g).map(b => parseInt(b, 16)));
    const rip = ripemd160(shaBytes);
    return Array.from(rip).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Stratum Prevhash Conversion ──────────────────────────────────────────

function stratumPrevhashToBlockchain(prevhashHex) {
    if (prevhashHex.length !== 64) return prevhashHex;
    // Step 1: undo per-group (4-byte) byte swap
    let internal = '';
    for (let i = 0; i < 64; i += 8) {
        for (let j = 6; j >= 0; j -= 2) {
            internal += prevhashHex.substring(i + j, i + j + 2);
        }
    }
    // Step 2: reverse entire 32 bytes → big-endian display order
    let result = '';
    for (let j = 62; j >= 0; j -= 2) {
        result += internal.substring(j, j + 2);
    }
    return result;
}

// ── Coinbase Parsing Helpers ─────────────────────────────────────────────
//
// Stratum splits the coinbase tx: coinbase1 + extranonce1 + extranonce2 + coinbase2.
// The web tool does NOT have extranonce values, so we parse each part separately:
//   - From coinbase1: extract scriptSig (height, tag) using known offsets.
//   - From coinbase2: extract outputs by finding the sequence marker + output section.

function hexToBytes(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function readU16LE(bytes, offset) {
    return bytes[offset] | (bytes[offset + 1] << 8);
}

function readU32LE(bytes, offset) {
    return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

function readU64LE(bytes, offset) {
    const lo = readU32LE(bytes, offset);
    const hi = readU32LE(bytes, offset + 4);
    return lo + hi * 0x100000000;
}

function readVarint(bytes, offset) {
    const first = bytes[offset];
    if (first < 0xfd) return { value: first, size: 1 };
    if (first === 0xfd) return { value: readU16LE(bytes, offset + 1), size: 3 };
    if (first === 0xfe) return { value: readU32LE(bytes, offset + 1), size: 5 };
    return { value: Number(readU64LE(bytes, offset + 1)), size: 9 };
}

// ── Coinbase Field Decoders ──────────────────────────────────────────────

/**
 * Extract the partial scriptSig from coinbase1 and the total scriptSig length.
 * Layout: version(4) + txin_count(1) + prevhash(32) + previndex(4) + scriptsig_len(varint) + partial_scriptsig
 * Returns { scriptSig: Uint8Array, totalLen: number, bytesInPart1: number }
 */
function extractScriptSigInfo(coinbase1Hex) {
    const bytes = hexToBytes(coinbase1Hex);
    // Skip: version(4) + txin_count(1) + prevhash(32) + previndex(4) = 41 bytes
    const scriptSigLenOffset = 41;
    if (bytes.length <= scriptSigLenOffset) {
        return { scriptSig: new Uint8Array(0), totalLen: 0, bytesInPart1: 0, coinbase1ByteLength: bytes.length };
    }

    const vi = readVarint(bytes, scriptSigLenOffset);
    const scriptSigOffset = scriptSigLenOffset + vi.size;
    // Cap to totalLen — coinbase1 may contain sequence+outputs past the scriptSig
    const maxBytes = Math.min(vi.value, bytes.length - scriptSigOffset);
    const partialSig = bytes.slice(scriptSigOffset, scriptSigOffset + maxBytes);
    return {
        scriptSig: partialSig,
        totalLen: vi.value,
        bytesInPart1: partialSig.length,
        coinbase1ByteLength: bytes.length,
        scriptSigOffset: scriptSigOffset
    };
}

function parseBlockHeight(scriptSig) {
    if (scriptSig.length < 2) return null;
    const hLen = scriptSig[0];
    if (hLen >= 1 && hLen <= 8 && scriptSig.length > hLen) {
        let height = 0;
        for (let i = 0; i < hLen; i++) {
            height += scriptSig[1 + i] * Math.pow(256, i);
        }
        return height;
    }
    return null;
}

function decodePrintableText(bytes) {
    try {
        const decoder = new TextDecoder('utf-8', { fatal: false });
        let text = decoder.decode(bytes);
        text = text.replace(/[\x00-\x1f\x7f]/g, '').trim();
        return text;
    } catch {
        let ascii = '';
        for (let i = 0; i < bytes.length; i++) {
            ascii += (bytes[i] >= 32 && bytes[i] <= 126) ? String.fromCharCode(bytes[i]) : '';
        }
        return ascii.trim();
    }
}

function parseCoinbaseTag(scriptSig) {
    if (scriptSig.length < 2) return '';
    const hLen = scriptSig[0];
    const raw = scriptSig.slice(1 + hLen);
    if (raw.length === 0) return '';
    return decodePrintableText(raw);
}

/**
 * Find the output section in the full coinbase transaction data.
 * fullBytes = coinbase1 + coinbase2 (concatenated, without extranonce).
 *
 * Layout: version(4) + txin_count(1) + prevhash(32) + previndex(4)
 *         + scriptsig_len(varint) + scriptsig + sequence(4)
 *         + output_count(varint) + outputs + locktime(4)
 *
 * Since extranonce bytes are missing from the concatenation, the scriptSig
 * length doesn't match the actual data. We scan for valid output structures
 * by trying each position as potential sequence start.
 *
 * minSeqOffset: earliest possible position for the sequence (after the known
 *               scriptSig data in coinbase1).
 */
function findOutputOffset(bytes, minSeqOffset, strict = true) {
    for (let seqStart = minSeqOffset; seqStart <= bytes.length - 6; seqStart++) {
        const outputCountOffset = seqStart + 4;
        if (outputCountOffset >= bytes.length) continue;

        const vi = readVarint(bytes, outputCountOffset);
        const outCount = vi.value;
        // Plausible output count: 1 to 20
        if (outCount < 1 || outCount > 20) continue;

        // Try to parse all outputs from this position to validate
        let pos = outputCountOffset + vi.size;
        let valid = true;
        let parsedOutputs = 0;

        for (let i = 0; i < outCount; i++) {
            if (pos + 9 > bytes.length) { valid = false; break; }
            pos += 8; // skip value

            if (pos >= bytes.length) { valid = false; break; }
            const svi = readVarint(bytes, pos);
            const scriptLen = svi.value;
            pos += svi.size;

            if (scriptLen > 520 || pos + scriptLen > bytes.length) { valid = false; break; }
            pos += scriptLen;
            parsedOutputs++;
        }

        if (!valid || parsedOutputs !== outCount) continue;

        // After all outputs, check locktime position
        const remaining = bytes.length - pos;
        if (strict) {
            // Exactly 4 bytes for locktime
            if (remaining === 4) {
                return { offset: outputCountOffset, seqStart: seqStart };
            }
        } else {
            // Allow 4 to 20 extra bytes (missing extranonce tolerance)
            // The locktime is somewhere in these remaining bytes
            if (remaining >= 4 && remaining <= 24) {
                return { offset: outputCountOffset, seqStart: seqStart };
            }
        }
    }

    return null;
}

/**
 * Pattern-based output detection for the straddling case.
 * When the output_count byte is in coinbase1 and outputs span across
 * both parts, we can't find a valid forward parse. Instead, we look
 * for recognizable script patterns near the end of coinbase2 and
 * extract individual outputs.
 * 
 * Returns an array of outputs directly (not an offset).
 */
async function detectOutputsByPattern(bytes) {
    const outputs = [];
    if (bytes.length < 38) return outputs;  // minimum: 8 value + 1 len + 25 script + 4 locktime

    // Scan for P2PKH pattern: 76 a9 14 {20 bytes hash} 88 ac
    // The script is 25 bytes, preceded by script_len byte (0x19) and 8-byte value
    for (let i = 0; i <= bytes.length - 25; i++) {
        if (bytes[i] === 0x76 && bytes[i + 1] === 0xa9 && bytes[i + 2] === 0x14 &&
            bytes[i + 23] === 0x88 && bytes[i + 24] === 0xac) {
            // Found P2PKH script at offset i, length 25
            // Check script_len byte before it
            if (i >= 1 && bytes[i - 1] === 0x19) {
                // Check that we have 8 value bytes before script_len
                if (i >= 9) {
                    const valueOffset = i - 9;
                    const valueSatoshis = readU64LE(bytes, valueOffset);
                    const h160 = bytesToHex(bytes.slice(i + 3, i + 23));
                    outputs.push({
                        value_satoshis: valueSatoshis,
                        value_bch: valueSatoshis / 100000000,
                        type: 'P2PKH',
                        cashaddr: hash160ToCashAddr(h160, 'P2PKH'),
                        legacy: await pubkeyHashToLegacyAddress(h160, 0x00)
                    });
                }
            }
        }
    }

    // Scan for P2SH pattern: a9 14 {20 bytes hash} 87
    for (let i = 0; i <= bytes.length - 23; i++) {
        if (bytes[i] === 0xa9 && bytes[i + 1] === 0x14 && bytes[i + 22] === 0x87) {
            // Script length = 23
            if (i >= 1 && bytes[i - 1] === 0x17) {
                if (i >= 9) {
                    const valueOffset = i - 9;
                    const valueSatoshis = readU64LE(bytes, valueOffset);
                    const h160 = bytesToHex(bytes.slice(i + 2, i + 22));
                    outputs.push({
                        value_satoshis: valueSatoshis,
                        value_bch: valueSatoshis / 100000000,
                        type: 'P2SH',
                        cashaddr: hash160ToCashAddr(h160, 'P2SH'),
                        legacy: await pubkeyHashToLegacyAddress(h160, 0x05)
                    });
                }
            }
        }
    }

    return outputs;
}

/**
 * Detect OP_RETURN outputs in coinbase2 for the straddling case.
 * OP_RETURN scripts start with 0x6a and can appear anywhere.
 * We look for value=0 + OP_RETURN pattern before the P2PKH/P2SH outputs.
 */
function detectOpReturnInCb2(bytes, knownOutputOffsets) {
    // Look for 8 zero-bytes (value=0) followed by a script starting with 6a
    for (let i = 0; i <= bytes.length - 12; i++) {
        // Skip positions already identified as other outputs
        if (knownOutputOffsets.some(o => i >= o - 9 && i <= o + 25)) continue;

        // Check for value = 0 (8 zero bytes)
        let allZero = true;
        for (let j = 0; j < 8; j++) {
            if (bytes[i + j] !== 0) { allZero = false; break; }
        }
        if (!allZero) continue;

        // Script length + OP_RETURN (0x6a)
        const scriptLen = bytes[i + 8];
        if (scriptLen > 0 && scriptLen < 100 && i + 9 < bytes.length && bytes[i + 9] === 0x6a) {
            if (i + 9 + scriptLen <= bytes.length) {
                const script = bytes.slice(i + 9, i + 9 + scriptLen);
                return {
                    value_satoshis: 0,
                    value_bch: 0,
                    type: 'OP_RETURN',
                    cashaddr: null,
                    legacy: null,
                    data: bytesToHex(script).substring(2) // skip the 6a opcode
                };
            }
        }
    }
    return null;
}

/**
 * Detect outputs that begin in coinbase1 after the scriptSig.
 * Handles the case where the pool places extranonce inside an OP_RETURN
 * output, causing the output section to start in coinbase1.
 *
 * Layout after scriptSig: sequence(4) + output_count(varint) + outputs...
 * We parse any outputs whose headers (value + scriptLen + script start) are
 * visible in coinbase1, even if the script data is incomplete (straddling
 * the extranonce gap).
 */
function detectOutputsInCoinbase1(coinbase1Bytes, scriptSigInfo) {
    const outputs = [];
    // Position right after the scriptSig data
    const afterSig = scriptSigInfo.scriptSigOffset + scriptSigInfo.totalLen;
    // Need at least sequence(4) + outCount(1) + value(8) + scriptLen(1) = 14 bytes
    if (afterSig + 14 > coinbase1Bytes.length) return outputs;

    // Verify sequence marker (ffffffff)
    const seq = readU32LE(coinbase1Bytes, afterSig);
    if (seq !== 0xffffffff) return outputs;

    const outCountOffset = afterSig + 4;
    const vi = readVarint(coinbase1Bytes, outCountOffset);
    const outCount = vi.value;
    if (outCount < 1 || outCount > 20) return outputs;

    let pos = outCountOffset + vi.size;

    for (let i = 0; i < outCount; i++) {
        // Need at least value(8) + scriptLen(1)
        if (pos + 9 > coinbase1Bytes.length) break;

        const valueSatoshis = readU64LE(coinbase1Bytes, pos);
        pos += 8;

        const svi = readVarint(coinbase1Bytes, pos);
        const scriptLen = svi.value;
        pos += svi.size;

        // How many script bytes are available in coinbase1?
        const availableScript = Math.min(scriptLen, coinbase1Bytes.length - pos);
        if (availableScript < 1) break;

        const partialScript = coinbase1Bytes.slice(pos, pos + availableScript);

        // OP_RETURN: first byte is 0x6a
        if (partialScript[0] === 0x6a) {
            // Collect whatever data bytes we have after the 0x6a opcode
            const dataBytes = partialScript.slice(1);
            outputs.push({
                value_satoshis: valueSatoshis,
                value_bch: valueSatoshis / 100000000,
                type: 'OP_RETURN',
                cashaddr: null,
                legacy: null,
                data: bytesToHex(dataBytes),
                partial: availableScript < scriptLen
            });
        }

        pos += scriptLen; // advance past declared script length
    }

    return outputs;
}

/**
 * Parse the full coinbase tag from the scriptSig.
 * Uses the scriptSig data from coinbase1 and any remaining scriptSig in the
 * concatenated data before the sequence marker.
 */
function parseFullCoinbaseTag(fullBytes, scriptSigInfo, outputInfo) {
    // scriptSig starts at offset 41 + varint_size in the full data
    // We know bytesInPart1 of scriptSig from coinbase1.
    // The full scriptSig is totalLen bytes, but extranonce is missing.
    // Everything from scriptSig start to the sequence is the actual scriptSig
    // (with extranonce gap, but tag data is typically at start and end).

    // Get scriptSig bytes only from part1 (known good data with height + tag)
    const scriptSig = scriptSigInfo.scriptSig;
    if (scriptSig.length < 2) return '';

    const hLen = scriptSig[0];
    const tagFromPart1 = scriptSig.slice(1 + hLen);

    // Also get tag data from the start of coinbase2 portion (before sequence)
    // coinbase2 starts at fullBytes[coinbase1ByteLength]
    const cb1Len = scriptSigInfo.coinbase1ByteLength;
    let tagFromPart2 = new Uint8Array(0);
    if (outputInfo && outputInfo.seqStart > cb1Len) {
        tagFromPart2 = fullBytes.slice(cb1Len, outputInfo.seqStart);
    }

    // Combine both parts
    const combined = new Uint8Array(tagFromPart1.length + tagFromPart2.length);
    combined.set(tagFromPart1, 0);
    combined.set(tagFromPart2, tagFromPart1.length);

    return decodePrintableText(combined);
}

/**
 * Parse outputs from the full coinbase data.
 */
async function parseOutputsFromFull(fullBytes, outputInfo) {
    const outputs = [];
    if (!outputInfo) return outputs;

    try {
        let offset = outputInfo.offset;

        const vi = readVarint(fullBytes, offset);
        const outputCount = vi.value;
        offset += vi.size;

        for (let i = 0; i < outputCount; i++) {
            if (offset + 8 > fullBytes.length) break;

            const valueSatoshis = readU64LE(fullBytes, offset);
            offset += 8;

            if (offset >= fullBytes.length) break;
            const svi = readVarint(fullBytes, offset);
            const scriptLen = svi.value;
            offset += svi.size;

            if (offset + scriptLen > fullBytes.length) break;

            const scriptPubKey = fullBytes.slice(offset, offset + scriptLen);
            offset += scriptLen;

            const parsed = await parseScriptPubKey(scriptPubKey);
            outputs.push({
                value_satoshis: valueSatoshis,
                value_bch: valueSatoshis / 100000000,
                ...parsed
            });
        }
    } catch (e) {
        console.error('Error parsing outputs:', e);
    }

    return outputs;
}

// ── Script Type Detection ────────────────────────────────────────────────

async function parseScriptPubKey(scriptPubKey) {
    const hex = bytesToHex(scriptPubKey);

    // P2PKH — OP_DUP OP_HASH160 PUSH20 <20B> OP_EQUALVERIFY OP_CHECKSIG
    if (scriptPubKey.length === 25 &&
        scriptPubKey[0] === 0x76 && scriptPubKey[1] === 0xa9 && scriptPubKey[2] === 0x14 &&
        scriptPubKey[23] === 0x88 && scriptPubKey[24] === 0xac) {
        const h160 = hex.substring(6, 46);
        return {
            type: 'P2PKH',
            cashaddr: hash160ToCashAddr(h160, 'P2PKH'),
            legacy: await pubkeyHashToLegacyAddress(h160, 0x00)
        };
    }

    // P2SH — OP_HASH160 PUSH20 <20B> OP_EQUAL
    if (scriptPubKey.length === 23 &&
        scriptPubKey[0] === 0xa9 && scriptPubKey[1] === 0x14 &&
        scriptPubKey[22] === 0x87) {
        const h160 = hex.substring(4, 44);
        return {
            type: 'P2SH',
            cashaddr: hash160ToCashAddr(h160, 'P2SH'),
            legacy: await pubkeyHashToLegacyAddress(h160, 0x05)
        };
    }

    // OP_RETURN — data carrier output
    if (scriptPubKey[0] === 0x6a) {
        return {
            type: 'OP_RETURN',
            cashaddr: null,
            legacy: null,
            data: hex.substring(2)
        };
    }

    // P2PK — <compressed/uncompressed pubkey> OP_CHECKSIG
    if (scriptPubKey[scriptPubKey.length - 1] === 0xac &&
        (scriptPubKey.length === 35 || scriptPubKey.length === 67)) {
        const pkLen = scriptPubKey[0];
        if (pkLen === scriptPubKey.length - 2) {
            const pubkeyHex = hex.substring(2, 2 + pkLen * 2);
            const h160 = await hash160(pubkeyHex);
            return {
                type: 'P2PK',
                cashaddr: hash160ToCashAddr(h160, 'P2PKH'),
                legacy: await pubkeyHashToLegacyAddress(h160, 0x00),
                pubkey: pubkeyHex
            };
        }
    }

    return {
        type: 'Unknown',
        cashaddr: null,
        legacy: null,
        script: hex
    };
}

// ── Difficulty Calculation ────────────────────────────────────────────────

const DIFF1_TARGET = BigInt('0x00000000FFFF0000000000000000000000000000000000000000000000000000');

function nbitsToDifficulty(nbitsHex) {
    const nbits = parseInt(nbitsHex, 16);
    const exp = nbits >>> 24;
    let coeff = nbits & 0x007fffff;
    if (nbits & 0x00800000) coeff = -coeff;

    const target = BigInt(coeff) * (1n << BigInt(8 * (exp - 3)));
    if (target <= 0n) return { str: 'N/A', raw: 0 };

    const diff = Number(DIFF1_TARGET) / Number(target);

    const units = [
        [1e18, 'E'], [1e15, 'P'], [1e12, 'T'],
        [1e9, 'G'], [1e6, 'M'], [1e3, 'K']
    ];

    for (const [threshold, unit] of units) {
        if (diff >= threshold) {
            return { str: `${(diff / threshold).toFixed(2)} ${unit}`, raw: diff };
        }
    }
    return { str: diff.toFixed(2), raw: diff };
}

// ── Parse mining.notify ──────────────────────────────────────────────────

async function parseMiningNotify(notifyData) {
    const result = {};

    let params;
    if (notifyData.params) {
        params = notifyData.params;
    } else if (Array.isArray(notifyData)) {
        params = notifyData;
    } else {
        throw new Error("Invalid format: expected 'params' in dict or array");
    }

    if (params.length < 9) {
        throw new Error(`Invalid mining.notify: expected at least 9 parameters, got ${params.length}`);
    }

    result.job_id = params[0];

    // Previous hash — proper Stratum prevhash conversion
    result.prevhash = stratumPrevhashToBlockchain(params[1]);

    const coinbasePart1 = params[2];
    const coinbasePart2 = params[3];

    // Extract scriptSig info from coinbase1 (partial — before extranonce)
    const scriptSigInfo = extractScriptSigInfo(coinbasePart1);
    const scriptSig = scriptSigInfo.scriptSig;

    // Block height (BIP-34)
    result.height = parseBlockHeight(scriptSig);

    // Concatenate coinbase1 + coinbase2
    const fullHex = coinbasePart1 + coinbasePart2;
    const fullBytes = hexToBytes(fullHex);
    const cb2Bytes = hexToBytes(coinbasePart2);

    // Try to find and parse outputs using multiple strategies:
    // Strategy 1: scan coinbase2 alone (sequence+outputs entirely in cb2)
    // Strategy 2: scan full concat (sequence+outputs may start in cb1, no extranonce gap)
    // Strategy 3: scan coinbase2 backwards from locktime (straddling with extranonce gap)

    let outputInfo = findOutputOffset(cb2Bytes, 0, true);
    let outputSource = cb2Bytes;
    let outputSourceIsCb2 = true;

    if (!outputInfo) {
        // Try full concatenation (strict)
        const minSeqOffset = scriptSigInfo.scriptSigOffset + 4;
        outputInfo = findOutputOffset(fullBytes, minSeqOffset, true);
        outputSource = fullBytes;
        outputSourceIsCb2 = false;
    }

    let patternOutputs = null;

    if (!outputInfo) {
        // Strategy 3: pattern-based detection in coinbase2
        // Scan for recognizable P2PKH/P2SH scripts with their value bytes
        patternOutputs = await detectOutputsByPattern(cb2Bytes);

        // Also detect OP_RETURN outputs in coinbase2 (value=0, script starts with 0x6a)
        if (patternOutputs && patternOutputs.length > 0) {
            const knownOffsets = [];
            // Collect approximate offsets of known outputs for exclusion
            for (let i = 0; i < cb2Bytes.length - 25; i++) {
                if (cb2Bytes[i] === 0x76 && cb2Bytes[i + 1] === 0xa9 && cb2Bytes[i + 2] === 0x14) {
                    knownOffsets.push(i);
                }
            }
            const opReturn = detectOpReturnInCb2(cb2Bytes, knownOffsets);
            if (opReturn) {
                patternOutputs.unshift(opReturn); // OP_RETURN typically first
            }
        }

        // Strategy 4: detect outputs (especially OP_RETURN) that start in coinbase1
        // This handles pools that place extranonce inside an OP_RETURN output,
        // causing the output section to begin in coinbase1.
        const cb1Bytes = hexToBytes(coinbasePart1);
        const cb1Outputs = detectOutputsInCoinbase1(cb1Bytes, scriptSigInfo);
        if (cb1Outputs.length > 0) {
            if (!patternOutputs) patternOutputs = [];
            // Prepend cb1 outputs (OP_RETURN is typically output #0)
            patternOutputs.unshift(...cb1Outputs);
        }
    }

    // Coinbase tag
    if (outputSourceIsCb2 && outputInfo) {
        const tagPart1 = parseCoinbaseTag(scriptSig);
        const preSeqEnd = outputInfo.seqStart >= 0 ? outputInfo.seqStart : 0;
        const tagPart2 = preSeqEnd > 0 ?
            decodePrintableText(cb2Bytes.slice(0, preSeqEnd)) : '';
        result.coinbaseTag = (tagPart1 + tagPart2).trim();
    } else if (outputInfo) {
        result.coinbaseTag = parseFullCoinbaseTag(fullBytes, scriptSigInfo, outputInfo);
    } else {
        // No output offset found — just use scriptSig from part1
        result.coinbaseTag = parseCoinbaseTag(scriptSig);
    }

    // ScriptSig hex for display
    result.scriptSig = bytesToHex(scriptSig);

    // Parse outputs
    if (patternOutputs && patternOutputs.length > 0) {
        // Pattern-based outputs (for straddling case)
        result.outputs = patternOutputs;
    } else {
        result.outputs = await parseOutputsFromFull(outputSource, outputInfo);
    }

    // Total reward
    result.totalReward = result.outputs.reduce((sum, o) => sum + o.value_satoshis, 0);

    // Merkle branches
    result.merkleBranches = params[4];

    // Additional fields
    result.version = params[5];
    result.nbits = params[6];
    result.ntime = params[7];
    result.clean_jobs = params[8];

    return result;
}

// ── Main Parse Function ──────────────────────────────────────────────────

async function parseNotify() {
    const input = document.getElementById('notifyInput').value.trim();
    const outputDiv = document.getElementById('output');

    if (!input) {
        outputDiv.innerHTML = '<fieldset><legend>Error</legend><p>Please enter a mining.notify JSON string</p></fieldset>';
        outputDiv.classList.add('visible');
        return;
    }

    try {
        const data = JSON.parse(input);
        const result = await parseMiningNotify(data);

        // Convert ntime to readable date
        const ntimeInt = parseInt(result.ntime, 16);
        const ntimeDate = new Date(ntimeInt * 1000).toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

        // Difficulty
        const diffResult = nbitsToDifficulty(result.nbits);

        // Block explorer base URL
        const explorerBase = 'https://bchexplorer.cash';

        // Build output HTML
        let html = '<fieldset><legend>Parsed Results</legend>';

        html += `<div class="output-item">
            <span class="output-label">Job ID:</span>
            <span class="output-value">${result.job_id}</span>
        </div>`;

        html += `<div class="output-item">
            <span class="output-label">Block Height:</span>
            <span class="output-value">${result.height !== null ? `<a href="${explorerBase}/block/${result.height}" target="_blank">${result.height}</a>` : 'Unable to extract'}</span>
        </div>`;

        html += `<div class="output-item">
            <span class="output-label">Previous Hash:</span>
            <span class="output-value"><a href="${explorerBase}/block/${result.prevhash}" target="_blank">${result.prevhash}</a></span>
        </div>`;

        if (result.coinbaseTag) {
            html += `<div class="output-item">
                <span class="output-label">Coinbase Tag:</span>
                <span class="output-value">${result.coinbaseTag}</span>
            </div>`;
        }

        if (result.scriptSig) {
            let ascii = '';
            for (let i = 0; i < result.scriptSig.length; i += 2) {
                const byte = parseInt(result.scriptSig.substr(i, 2), 16);
                ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
            }
            html += `<div class="output-item">
                <span class="output-label">ScriptSig:</span>
                <span class="output-value">${ascii}</span>
            </div>`;
        }

        html += `<div class="output-item">
            <span class="output-label">Block Version:</span>
            <span class="output-value">${result.version} (0x${parseInt(result.version, 16).toString(16)})</span>
        </div>`;

        html += `<div class="output-item">
            <span class="output-label">Difficulty (nBits):</span>
            <span class="output-value">${result.nbits} (${diffResult.str})</span>
        </div>`;

        html += `<div class="output-item">
            <span class="output-label">Timestamp (nTime):</span>
            <span class="output-value">${result.ntime} (${ntimeDate})</span>
        </div>`;

        html += `<div class="output-item">
            <span class="output-label">Clean Jobs:</span>
            <span class="output-value">${result.clean_jobs}</span>
        </div>`;

        // Total reward
        html += `<div class="output-item">
            <span class="output-label">Block Reward:</span>
            <span class="output-value">${(result.totalReward / 100000000).toFixed(8)} BCH (${result.totalReward.toLocaleString()} satoshis)</span>
        </div>`;

        // Coinbase outputs
        if (result.outputs && result.outputs.length > 0) {
            html += '<div class="coinbase-outputs">';
            html += '<div class="coinbase-title">Coinbase Outputs:</div>';

            result.outputs.forEach((output, i) => {
                html += '<div class="output-entry">';
                html += `<div class="output-entry-title">Output ${i + 1}:</div>`;
                html += `<div class="output-item">
                    <span class="output-label">Value:</span>
                    <span class="output-value">${output.value_bch.toFixed(8)} BCH (${output.value_satoshis.toLocaleString()} satoshis)</span>
                </div>`;
                html += `<div class="output-item">
                    <span class="output-label">Type:</span>
                    <span class="output-value">${output.type}</span>
                </div>`;

                if (output.cashaddr) {
                    html += `<div class="output-item">
                        <span class="output-label">CashAddr:</span>
                        <span class="output-value"><a href="${explorerBase}/address/${output.cashaddr}" target="_blank">${output.cashaddr}</a></span>
                    </div>`;
                }

                if (output.legacy) {
                    html += `<div class="output-item">
                        <span class="output-label">Legacy:</span>
                        <span class="output-value">${output.legacy}</span>
                    </div>`;
                }

                if (output.type === 'OP_RETURN' && output.data) {
                    html += `<div class="output-item">
                        <span class="output-label">Data (hex):</span>
                        <span class="output-value">${output.data}${output.partial ? ' (partial — remaining bytes are in extranonce)' : ''}</span>
                    </div>`;
                    try {
                        const bytes = output.data.match(/.{2}/g).map(b => parseInt(b, 16));
                        const readable = bytes.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
                        if (bytes.some(b => b >= 32 && b <= 126)) {
                            html += `<div class="output-item">
                                <span class="output-label">Readable:</span>
                                <span class="output-value">${readable}</span>
                            </div>`;
                        }
                    } catch { }
                }

                if (output.type === 'P2PK' && output.pubkey) {
                    html += `<div class="output-item">
                        <span class="output-label">Pubkey:</span>
                        <span class="output-value">${output.pubkey}</span>
                    </div>`;
                }

                html += '</div>';
            });

            html += '</div>';
        }

        // Merkle branches
        if (result.merkleBranches && result.merkleBranches.length > 0) {
            html += '<div class="coinbase-outputs">';
            html += `<div class="coinbase-title">Merkle Branch (${result.merkleBranches.length} levels ≈ ${Math.pow(2, result.merkleBranches.length)} txs):</div>`;
            result.merkleBranches.forEach((branch, i) => {
                html += `<div class="output-item">
                    <span class="output-label">[${i}]</span>
                    <span class="output-value">${branch}</span>
                </div>`;
            });
            html += '</div>';
        }

        html += '</fieldset>';

        outputDiv.innerHTML = html;
        outputDiv.classList.add('visible');

    } catch (e) {
        outputDiv.innerHTML = `<fieldset><legend>Error</legend><p>${e.message}</p></fieldset>`;
        outputDiv.classList.add('visible');
    }
}

// ── UI Helpers ────────────────────────────────────────────────────────────

function clearInput() {
    document.getElementById('notifyInput').value = '';
    document.getElementById('output').innerHTML = '';
    document.getElementById('output').classList.remove('visible');
    document.getElementById('notifyInput').focus();
}

// Allow Enter key to parse
document.getElementById('notifyInput').addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        parseNotify();
    }
});

document.getElementById('notifyInput').addEventListener('keypress', function (e) {
    if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        parseNotify();
    }
});
