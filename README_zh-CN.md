# BCH Stratum Mining.Notify 解析器

[English](README.md) | [中文](README_zh-CN.md)

> 轻量级纯前端工具，用于解析比特币现金（BCH）Stratum 协议的 `mining.notify` 消息——无需服务器，无任何依赖，打开即用。

## 💾 在线演示

**[→ 在线体验](https://harshycn.github.io/bch-pool-checkr/)**

## ✨ 功能特性

| 分类 | 说明 |
|------|------|
| **区块信息** | 区块高度（BIP-34）、前一区块哈希、版本号、难度、时间戳 |
| **Coinbase 解析** | 完整 scriptSig 解码，矿池标识（coinbase tag）提取 |
| **地址支持** | CashAddr（`bitcoincash:q…`/`p…`） + 传统格式（`1…`/`3…`） |
| **脚本类型** | P2PKH、P2SH、P2PK（公钥 → HASH160 推导）、OP_RETURN |
| **区块奖励** | 输出总额显示，逐笔输出明细 |
| **区块浏览器** | 区块高度、前一哈希、地址均可直接跳转 [bchexplorer.cash](https://bchexplorer.cash) |
| **界面风格** | 复古 Macintosh System 6 风格 🖥️ |

## 🚀 使用方法

1. 在浏览器中打开 [index.html](index.html)，或访问 **[在线演示](https://harshycn.github.io/bch-pool-checkr/)**
2. 粘贴 BCH `mining.notify` JSON 消息
   - 可以使用 [bch-stratum-inspector](https://github.com/Harshycn/bch-stratum-inspector) 的 `--debug` 模式抓取
3. 点击 **Parse** 或按 <kbd>Enter</kbd>

### 输入示例

```json
{"method":"mining.notify","params":["jobId","prevhash","coinbase1","coinbase2",
["merkle_branch"],"version","nbits","ntime",clean_jobs]}
```

## 🔧 技术细节

- **ScriptSig 与 Coinbase Tag 的区别** — `ScriptSig` 作为 Coinbase 交易的解锁脚本，其内容并不用于签名验证，而是可以包含任意数据（BIP-34 规定通常以区块高度开头）；而 **Coinbase Tag** 是矿池特意写入这段任意附加数据中的一小段特定字符或标记。矿池利用它来对外宣示该区块归属，或者是作为存放额外随机数（Nonce）的地方。本工具专门提取该标识。
- **OP_RETURN 输出** — `OP_RETURN` 是一种可被网络中继但不可花费的交易输出类型，矿池常用它在 coinbase 交易中嵌入任意元数据（如区块承诺、合并挖矿标记等）。解析器会正常识别此类输出并展示其十六进制原始数据和可读文本；但由于 `OP_RETURN` 脚本不包含公钥哈希或脚本哈希，因此不存在对应的 CashAddr / Legacy 地址。
- **跨分片解析** — 处理 Stratum 协议中 `coinbase1`/`coinbase2` 之间缺少 extranonce 字节的情况。采用四级检测策略：coinbase2 正向扫描 → 完整拼接正向扫描 → 基于脚本模式的特征匹配 → coinbase1 输出检测（处理 extranonce 嵌入 OP_RETURN 的情况）。
- **CashAddr 编码** — 完整实现 CashAddr 规范（BCH 专用 polymod、5-bit 转换、`bitcoincash:` 前缀）。
- **P2PK 支持** — 对压缩/非压缩公钥进行 SHA-256 → RIPEMD-160 哈希，推导出对应的 CashAddr 地址。

## ☕ 捐赠

如果这个工具对你有帮助，请考虑请我喝杯咖啡 ☕

- **BTC:** `bc1qftzsn5py6gcy5lzlc9hc6usmqy8wqgzsamg7fh`
- **BCH:** `bitcoincash:qqj9rrt85mzdhf3mknppz7xvkxnxlxel9ynfku43nh`

## 📄 许可证

MIT

## 🙏 致谢

- 原始项目：[skot/pool_checkr](https://github.com/skot/pool_checkr)
- BCH 逻辑移植自：[bch-stratum-inspector](https://github.com/Harshycn/bch-stratum-inspector)
- BCH Solo 矿池：[Harshy's Pool](https://harshy.site/)
- System 6 界面：[sakofchit/system.css](https://github.com/sakofchit/system.css)
- Chicago Kare 字体：Duane King — [duaneking/Chicago-Kare](https://github.com/duaneking/Chicago-Kare)（MIT 许可）
