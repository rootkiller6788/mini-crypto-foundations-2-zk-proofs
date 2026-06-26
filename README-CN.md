# Mini Crypto Foundations 2 — 零知识证明（Zero-Knowledge Proofs）

**从零开始、零依赖的 C 语言实现**，涵盖零知识证明系统及其密码学构建模块。本模块覆盖基础理论与构造——交互式证明、Sigma 协议、承诺方案、GMW 协议、非交互式零知识（NIZK）、知识指数假设和 zkSNARK——将研究生级密码学理论转化为可运行的 C 代码。

## 子模块总览

| 子模块 | 主题 | 参考课程 |
|-----------|--------|-------------|
| [mini-commitment-schemes](mini-commitment-schemes/) | 比特承诺、Pedersen 承诺（完美隐藏）、基于哈希的承诺（统计隐藏）、Merkle 树向量承诺、素数域模运算、隐藏性与绑定性权衡 | MIT 6.875, Stanford CS355 |
| [mini-gmw-graph-3coloring-zk](mini-gmw-graph-3coloring-zk/) | GMW 协议（Goldreich-Micali-Wigderson 1986）、图三着色 NP 完全性、面向所有 NP 的交互式零知识证明、比特承诺、零知识模拟器、完备性/可靠性/零知识三元悖论 | MIT 6.875, Stanford CS355 |
| [mini-interactive-proof-systems](mini-interactive-proof-systems/) | 交互式证明系统、IP=PSPACE（Shamir 1992）、求和检查协议（LFKN 1990）、GKR 双重高效协议、布尔公式的算术化、图非同构零知识证明 | MIT 6.845, Stanford CS254, Princeton COS 522 |
| [mini-knowledge-of-exponent](mini-knowledge-of-exponent/) | 知识指数假设（KEA1/KEA2/KEA3）、离散对数与 Diffie-Hellman 问题、密码学群论、双线性配对、基于可提取性假设的 SNARK 构造 | MIT 6.876, Stanford CS355 |
| [mini-nizk-common-reference-string](mini-nizk-common-reference-string/) | 公共参考字符串（CRS）模型中的非交互式零知识证明、基于 Sigma 协议的 Fiat-Shamir 变换、安全素数群上的 Pedersen 承诺、带后门的 NIZK 模拟器、面向 NP 的 NIZK 证明 | MIT 6.876, Stanford CS355 |
| [mini-sigma-protocols-fiat-shamir](mini-sigma-protocols-fiat-shamir/) | Sigma 协议（Schnorr、Chaum-Pedersen、Guillou-Quisquater）、三轮诚实验证者零知识、协议组合（AND/OR/EQ）、Fiat-Shamir 启发式、从 Sigma 协议构造非交互式数字签名 | MIT 6.875, Stanford CS355 |
| [mini-zero-knowledge-simulators](mini-zero-knowledge-simulators/) | 零知识模拟框架（完美/统计/计算）、用于零知识证明的经典 NP 完全问题、并发零知识、模拟器调度、Sigma 协议、Fiat-Shamir 变换 | MIT 6.875, Stanford CS355 |
| [mini-zksnark-qap-r1cs](mini-zksnark-qap-r1cs/) | zkSNARK 构造（Groth16）、R1CS 算术约束系统、二次算术程序（QAP）、电路到 R1CS 编译、基于配对的多项式承诺、可信设置（Powers-of-Tau）、有限域上的 FFT/NTT | MIT 6.876, Stanford CS251 |

## 设计理念

- **零外部依赖** — 纯 C（C99/C11），仅使用 `libc` 和 `libm`
- **模块自包含** — 每个目录自带 `Makefile`、`include/`、`src/`、`docs/`、`demos/`、`tests/`
- **理论到代码的映射** — 每个模块的 .h 文件结构直接对应教科书中的定义、定理和协议步骤
- **教学保真度** — 实现展示完整的协议流程（承诺 → 挑战 → 响应 → 验证），而非封装不透明的密码学 API

## 构建方式

每个模块相互独立。进入模块目录后运行：

```bash
cd mini-commitment-schemes
make all    # 构建全部
make test   # 运行测试
```

需要 **GCC** 和 **GNU Make**。

## 项目结构

```
mini-crypto-foundations-2-zk-proofs/
├── mini-commitment-schemes/           # 比特承诺、Pedersen 承诺、Merkle 树向量承诺
├── mini-gmw-graph-3coloring-zk/       # 图三着色 GMW 零知识协议
├── mini-interactive-proof-systems/    # 交互式证明系统、求和检查、GKR、算术化
├── mini-knowledge-of-exponent/        # 知识指数假设、离散对数、基于可提取性的 SNARK
├── mini-nizk-common-reference-string/  # 基于 CRS 模型的非交互式零知识证明
├── mini-sigma-protocols-fiat-shamir/  # Sigma 协议、Fiat-Shamir 变换
├── mini-zero-knowledge-simulators/    # 零知识模拟框架、并发零知识
└── mini-zksnark-qap-r1cs/             # zkSNARK Groth16、QAP、R1CS、可信设置
```

## 许可证

MIT
