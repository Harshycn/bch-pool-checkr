# BCH Stratum Mining.Notify Parser

[English](README.md) | [中文](README_zh-CN.md)

> A lightweight, client-side tool for parsing Bitcoin Cash (BCH) Stratum `mining.notify` messages — no server, no dependencies, just open and paste.

## 💾 Live Demo

**[→ Try it online](https://harshycn.github.io/bch-pool-checkr/)**

## ✨ Features

| Category | Details |
|----------|---------|
| **Block Info** | Height (BIP-34), previous hash, version, difficulty, timestamp |
| **Coinbase Parsing** | Full scriptSig decode, coinbase tag (pool identity) extraction |
| **Address Support** | CashAddr (`bitcoincash:q…`/`p…`) + Legacy (`1…`/`3…`) |
| **Script Types** | P2PKH, P2SH, P2PK (pubkey → HASH160), OP_RETURN |
| **Block Reward** | Total output value with per-output breakdown |
| **Explorer Links** | Block height, prevhash, and addresses link to [bchexplorer.cash](https://bchexplorer.cash) |
| **UI** | Retro System 6 aesthetic 🖥️ |

## 🚀 Usage

1. Open [index.html](index.html) in your browser, or visit the **[live demo](https://harshycn.github.io/bch-pool-checkr/)**
2. Paste a BCH `mining.notify` JSON message
   - Capture one using [bch-stratum-inspector](https://github.com/Harshycn/bch-stratum-inspector) with `--debug` flag
3. Click **Parse** or press <kbd>Enter</kbd>

### Example Input

```json
{"method":"mining.notify","params":["jobId","prevhash","coinbase1","coinbase2",
["merkle_branch"],"version","nbits","ntime",clean_jobs]}
```

## 🔧 Technical Details

- **Prevhash Conversion** — Stratum sends the previous block hash as 8 little-endian uint32 words; the parser reverses bytes within each 4-byte group, then reverses the entire hash to produce the standard block explorer format.
- **BIP-34 Height** — Block height is extracted from the coinbase scriptSig per BIP-34 encoding.
- **Coinbase Tag** — The pool identity string is decoded from the scriptSig bytes following the BIP-34 height push (supports UTF-8, including CJK and emoji).
- **ScriptSig vs Coinbase Tag** — The `ScriptSig` is the coinbase transaction's unlocking script; since there is no real UTXO to spend, it can carry arbitrary data (BIP-34 mandates a block-height prefix). The **Coinbase Tag** is just a small substring within that arbitrary data — the pool's self-identifying marker.
- **OP_RETURN Outputs** — `OP_RETURN` is a provably unspendable output type commonly used by pools to embed arbitrary metadata (e.g. block commitments, merge-mining tags) in the coinbase. The parser detects these outputs and displays their hex data and readable text; however, because `OP_RETURN` scripts contain no public-key hash, no CashAddr / Legacy address can be derived.
- **Cross-Part Parsing** — Handles the Stratum protocol split where `coinbase1`/`coinbase2` are missing extranonce bytes. Uses a 4-strategy pipeline: forward scan on `coinbase2` → forward scan on full concatenation → pattern-based detection in `coinbase2` → output detection in `coinbase1` (for pools that embed extranonce inside OP_RETURN).
- **CashAddr Encoding** — Implements the full CashAddr spec (BCH-specific polymod, 5-bit conversion, `bitcoincash:` HRP).
- **P2PK Support** — Compressed/uncompressed public keys are hashed (SHA-256 → RIPEMD-160) to derive the corresponding CashAddr address.

## 📄 License

MIT

## 🙏 Credits

- Original project by [skot](https://github.com/skot/pool_checkr)
- BCH logic ported from [bch-stratum-inspector](https://github.com/Harshycn/bch-stratum-inspector)
- BCH solo mining pool by [Harshy's Pool](https://harshy.site/)
- System 6 UI by [sakofchit/system.css](https://github.com/sakofchit/system.css)
- Chicago Kare font by Duane King — [duaneking/Chicago-Kare](https://github.com/duaneking/Chicago-Kare) (MIT)
