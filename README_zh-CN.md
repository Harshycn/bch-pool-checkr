# BCH Stratum Mining.Notify 解析器

[English](README.md) | [中文](README_zh-CN.md)

> 轻量级纯前端工具，用于解析比特币现金（BCH）Stratum 协议的 `mining.notify` 消息——无需服务器，无任何依赖，打开即用。

## 💾 在线演示

**[→ 在线体验](https://harshycn.github.io/pool_checkr/)**

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

1. 在浏览器中打开 [index.html](index.html)，或访问 **[在线演示](https://harshycn.github.io/pool_checkr/)**
2. 粘贴 BCH `mining.notify` JSON 消息
   - 可以使用 [bch-stratum-inspector](https://github.com/Harshycn/bch-stratum-inspector) 的 `--debug` 模式抓取
3. 点击 **Parse** 或按 <kbd>Enter</kbd>

### 输入示例

```json
{"method":"mining.notify","params":["jobId","prevhash","coinbase1","coinbase2",
["merkle_branch"],"version","nbits","ntime",clean_jobs]}
```

## 🔧 技术细节

- **前一区块哈希转换** — Stratum 协议将前一区块哈希以 8 个小端序 uint32 形式发送；解析器先对每 4 字节组内部做字节翻转，再对整个 32 字节做翻转，得到区块浏览器中显示的标准格式。
- **BIP-34 区块高度** — 按照 BIP-34 规范从 coinbase 交易的 scriptSig 中提取区块高度。
- **矿池标识（Coinbase Tag）** — 从 scriptSig 中 BIP-34 高度推送之后的字节解码矿池标识字符串（支持 UTF-8，包括中文和 Emoji）。
- **ScriptSig 与 Coinbase Tag 的区别** — `ScriptSig` 作为 Coinbase 交易的解锁脚本，其内容并不用于签名验证，而是可以包含任意数据（BIP-34 规定通常以区块高度开头）；而 **Coinbase Tag** 是矿池特意写入这段任意附加数据中的一小段特定字符或标记，它仅仅是 `ScriptSig` 完整数据的一部分，用来对外宣示该区块归属。
- **OP_RETURN 输出** — `OP_RETURN` 是一种可被网络中继但不可花费的交易输出类型，矿池常用它在 coinbase 交易中嵌入任意元数据（如区块承诺、合并挖矿标记等）。解析器会正常识别此类输出并展示其十六进制原始数据和可读文本；但由于 `OP_RETURN` 脚本不包含公钥哈希或脚本哈希，因此不存在对应的 CashAddr / Legacy 地址。
- **跨分片解析** — 处理 Stratum 协议中 `coinbase1`/`coinbase2` 之间缺少 extranonce 字节的情况。采用四级检测策略：coinbase2 正向扫描 → 完整拼接正向扫描 → 基于脚本模式的特征匹配 → coinbase1 输出检测（处理 extranonce 嵌入 OP_RETURN 的情况）。
- **CashAddr 编码** — 完整实现 CashAddr 规范（BCH 专用 polymod、5-bit 转换、`bitcoincash:` 前缀）。
- **P2PK 支持** — 对压缩/非压缩公钥进行 SHA-256 → RIPEMD-160 哈希，推导出对应的 CashAddr 地址。

## 📄 许可证

MIT

## 🙏 致谢

- 原始项目：[skot/pool_checkr](https://github.com/skot/pool_checkr)
- BCH 逻辑移植自：[bch-stratum-inspector](https://github.com/Harshycn/bch-stratum-inspector)
- System 6 界面：[sakofchit/system.css](https://github.com/sakofchit/system.css)
- Chicago Kare 字体：Duane King — [duaneking/Chicago-Kare](https://github.com/duaneking/Chicago-Kare)（MIT 许可）
