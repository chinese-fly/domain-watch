# domain-watch

可以放进 cron 的仿冒域名监控。

[English](README.md) | 简体中文

多数抢注检测工具是一次性的：跑一遍，出一张表，关掉终端。这只回答了"现在有什么"，
别的什么都没答。而品牌每天早上真正要回答的问题是**"跟昨天比变了什么"**——
这需要历史、需要打分、需要一份能贴进工单的报告。

这三样这里都有。

## 它做什么

1. **生成**目标域名的所有可能变体，覆盖 15 条置换规则（比特翻转、同形字、西里尔字母、
   击键插入、漏字、调换、加连字符、子域化、元音替换、复数化、重复字符、替换、追加字符、
   词典拼接、换 TLD）。
2. **解析**这些候选的 DNS，用有上限的线程池。
3. **打分**，每个权重信号都保留理由。
4. **入库**，每次运行写进 SQLite，并与上一次做对比。
5. **出报告**，支持终端表格、Markdown、JSON。

## 快速开始

```bash
python -m dwatch scan example.com
```

```text
   SCORE  DOMAIN        RULE           ADDRESSES
------------------------------------------------
!!    83  examp1e.com   homoglyph      93.184.216.34
!     48  exanple.com   homoglyph      45.33.32.156
      28  examp-le.com  hyphenation    45.33.32.157

251 candidates generated, 3 resolving
```

同一个库再跑一次，就能拿到差异：

```bash
python -m dwatch diff example.com
```

```text
+ examp1e.co (score 48)
- oid-example.com (was 38)
~ example.net 20 -> 48
```

其他入口：

```bash
python -m dwatch scan example.com --format markdown   # 贴进工单
python -m dwatch scan example.com --format json       # 喂给看板
python -m dwatch scan example.com --include-dead      # 连解析不出的也列出
python -m dwatch history example.com                  # 历史运行记录
python -m dwatch rules                                # 列出 15 条规则
```

## 实测结果

2026-11-16 对 `github.com` 跑全 15 条规则，默认解析器：

```text
261 candidates generated, 130 resolving
```

真实输出，截取表格前几行：

```text
   SCORE  DOMAIN      RULE           ADDRESSES
----------------------------------------------
!     48  eithub.com  bitsquatting   13.248.243.5, 76.223.105.230
!     48  fithub.com  bitsquatting   5.22.145.121, 5.22.145.16
!     48  gathub.com  bitsquatting   216.250.120.46
!     48  ghthub.com  bitsquatting   38.4.85.252
!     48  gi4hub.com  bitsquatting   177.210.210.253
!     48  gith5b.com  bitsquatting   54.198.53.48
!     48  githud.com  homoglyph      66.81.203.137
!     48  githuḅ.com  homoglyph      127.0.0.1
!     48  githüb.com  homoglyph      2.57.91.91
```

这段输出里有两处值得注意，也正是"要打分而不是平铺列表"的理由：

- `githuḅ.com` 解析到 `127.0.0.1`。这不是网站，是刻意的黑洞配置或者配错了，
  混在 130 行按字母排的列表里根本不会有人看见。
- `githüb.com` 和 `githeb.com` 解析到**同一个**地址 `2.57.91.91`。
  两个仿冒域名落在同一台主机上，这是注册行为模式，不是巧合。

测试：

```text
$ python -m unittest      # 108 tests, ~0.1s
Ran 108 tests in 0.104s
OK
```

## 打分

每一分都可追溯。`explain()` 返回明细，Markdown 报告把理由打在 `Why` 列里，
所以一条结论是能被论证的，不是被断言的。

| 信号 | 分值 | 理由 |
|---|---:|---|
| 能解析 | 20 | 死掉的候选不占用任何人的时间 |
| 有邮件交换（MX） | 15 | 钓鱼要先能收信，不只是能出网页 |
| 与品牌共享源站 IP | 15 | DNS 指向了真实基础设施 |
| 易误读规则（同形字／西里尔／比特翻转） | 18 | 就是为了让人看错而造的 |
| 普通错拼规则 | 8 | 很常见，通常无害 |
| 与主标签仅差一个字符 | 10 | 拼写越接近，越容易误触 |
| 可疑 TLD | 12 | 先验，单独从不定性 |
| **仿冒组合**（易误读规则 + MX 或共享 IP） | **+20** | 关键是组合，不是任何单一信号 |

分段：`high` ≥ 70，`medium` ≥ 40，`low` > 0，`info` = 0。

组合规则存在的原因：把各部分相加会**低估**这个工具最该抓的那种情况。
一个同形字域名，活着、收邮件、指向品牌自己的地址，各部分加起来只有 68 分——
低于 `high`——而一个带垃圾 TLD 的停放错拼域名却能漂到接近它的位置。这是反的。
`impersonation kit` 这一项就是修正，并且有测试钉住它
（`test_homoglyph_on_real_ip_is_high`）。

## 设计取舍

**为什么置换引擎要单独成模块。** 上游项目把生成、解析、CLI 全塞进一个脚本，
导致规则无法在不联网的情况下断言。这里每条规则都是对标签的纯函数，
所以 `tests/test_permute.py` 钉的是精确输出——`transposition("abcdef")`
必须恰好有两个相邻位置不同，而不是"返回了点东西"。

**为什么用 `Resolver` 协议而不是直接调 `socket`。** 测试用 `FakeResolver`，
完全不碰网络。108 个测试跑 0.1 秒，靠的就是这个。

**为什么用 SQLite 而不是 JSON 文件。** 一次运行 130 行，二十次就是 2,600 行。
做差异需要按域名索引查询，做清理需要不重写整个文件的删除。每次扫描后都会调
`prune(keep=20)`，所以数据库有上限。

**为什么分数不是概率。** 这些权重是序数性的。它们回答"这两个我先看哪个"，
不回答"这个域名有 62% 是恶意的"。假装是后者，会让报告显得比证据更有权威。

## 它不做什么

- **不做截图和内容分析。** 停放页和活的钓鱼站，只要 DNS 一样，分数就一样。
  加一层无头浏览器是最明显的下一步，这里刻意没做。
- **不做证书透明度或 WHOIS 关联。** 注册时间是可获得的最强信号之一，这里不读。
  解析器接口能再挂一个数据源，不用重构。
- **分数没有用真实数据标定过。** 阈值是判断，不是测量。真要部署的人，
  应该先拿自己的流量重新调 `WEIGHTS`，再决定凌晨三点要不要为一个 `high` 打电话。
- **`tld-swap` 需要显式给池子。** 不给 `--tld-pool` 就什么都不产出，
  而不是生成全部 1,500 个 TLD 去打爆解析器。
- **没有限速。** 261 个候选就是 261 次查询一起发。请从你被允许产生 DNS 流量的
  基础设施上运行。

## 规则设计

15 条规则按利用的东西分组，每一条都要对得上一个钉死精确输出的测试，
而不是"返回了什么就行"：

| 分组 | 规则 | 利用的是什么 |
|---|---|---|
| 视觉混淆 | `homoglyph`、`cyrillic`、`bitsquatting` | 骗人的眼睛，不是机器 |
| 手指打滑 | `insertion`、`omission`、`repetition`、`transposition`、`replacement` | QWERTY 相邻键 |
| 词义变体 | `hyphenation`、`vowel-swap`、`plural`、`addition`、`dictionary` | 品牌被念出来 / 写出来的方式 |
| 基础设施 | `subdomain`、`tld-swap` | 会敲完整 URL 的人 |

两处刻意不走朴素写法：

- **`plural` 用追加。** 把后缀插在单词中间任意位置（`example` → `exasmple`）
  会生成没人会输入的字符串。这里用追加，带连字符的标签则逐段变形。
- **`tld-swap` 需要显式给池子。** 不给 `--tld-pool` 就什么都不产出，
  而不是生成全部 1,500 个 TLD 去打爆解析器。

Apache-2.0。

## 依赖

Python 3.10+，只用标准库——没有 `requests`，没有 `dnspython`，没有 `tldextract`。
这是刻意的：一个因为依赖解析出问题而启动不了的监控脚本，比一张稍弱的
后缀表要糟糕得多。

## 结构

```text
dwatch/
  glyphs.py     替换表
  permute.py    15 条规则 + 域名切分
  resolver.py   多线程 DNS，可替换以便测试
  score.py      加权信号，可追溯
  store.py      SQLite 历史 + 差异
  report.py     表格 / markdown / json
  scanner.py    编排
  cli.py        参数解析
tests/          108 个测试，不联网
```
