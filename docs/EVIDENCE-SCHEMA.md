# EVIDENCE-SCHEMA — 输出契约

**这份文件是给写集成的人看的。** 不是设计稿，是承诺：哪些字段现在就有、哪些在 v0.2、哪些永远不会变。

> 所有「现状」均取自实测输出（`./audit.sh --json`，2026-10-22，含 docker 靶场与 8.5.12 容器）。
> 本文档里出现的每个字段名、每个数字、每个枚举词，都能在 `audit.sh` / `probe.php` 里 grep 到。

---

## 0. 先划清：哪些是「今天就有」

**这张表最重要。** 标 🎯 的，v0.1 都没有。

| 项 | v0.1 现状 | v0.2 目标 | 状态 |
|:--|:--|:--|:--|
| `schema_version` | ✅ 输出 `"1.0"` | 保持 `1.0`，加字段升 `1.1` | **今天就有** |
| `tool` / `generated_at` / `host` | ✅ 有 | 不变 | **今天就有** |
| `advisory` | ✅ 有（CVE / CVSS / 区间 / 修复版 / EOL 分支） | 不变 | **今天就有** |
| `verdict` | ✅ **五值**（见 §1.1） | 不变 | **今天就有** |
| `verdict_label_zh` / `action` / `exit_code` | ✅ 有 | 不变 | **今天就有** |
| `targets_found` / `summary` | ✅ 有 | 不变 | **今天就有** |
| `installs[].findings[]` | ✅ 有（`id` / `severity` / `title` / `detail`） | 不变，作为证据的**引用目标** | **今天就有** |
| `installs[].tier` / `tier_label` / `tier_reason` | ✅ **有**（每个 install 一份） | `tier_reason` 转枚举，中文挪到 `tier_reason_text` | **今天就有** |
| `overrides.files[]` | ✅ 有（含 `effect`） | 不变，作为引用目标 | **今天就有** |
| `docker[].verdict_reason` | ✅ 有 | 不变 | **今天就有** |
| `docker[].tier` | ❌ **没有** | 补上，与 `installs[]` 对齐 | 🎯 **目标** |
| `mitigation_impact` / `warnings` | ✅ 有 | 不变 | **今天就有** |
| **`evidence[]`** | ❌ **不存在** | `1.1` 新增，引用式 | 🎯 **目标** |
| **`reproduce`** | ❌ **不存在** | `1.1` 新增（顶层一条命令） | 🎯 **目标** |
| **`raw_sha256`** | ❌ **不存在** | `1.1` 新增（evidence 内字段） | 🎯 **目标** |

⚠️ **`verdict: patched_but_partial` 不是合法值，任何版本都不会有。别写。**

---

## 1. v0.1 顶层结构（16 个字段，逐字）

```json
{
  "schema_version": "1.0",
  "tool": {"name": "php-exposure-audit", "component": "audit.sh", "version": "0.1.0"},
  "generated_at": "2026-10-22T13:58:27Z",
  "host": {"hostname": "...", "os": "Darwin", "kernel": "25.6.0"},
  "advisory": {"cve_ids": ["CVE-2026-109618", "CVE-2026-109619"], "cvss": "9.2",
               "affected_range": {"min": "...", "max": "..."},
               "fixed_versions": {"8.2": "...", "8.3": "...", "8.4": "...", "8.5": "8.5.12"},
               "eol_branches_without_official_fix": ["5.4", "...", "8.1"]},
  "verdict": "not_applicable",
  "verdict_label_zh": "未发现 PHP",
  "action": "…下一步该干什么…",
  "exit_code": 2,
  "targets_found": 0,
  "summary": {"install_count": 0, "affected": 0, "patched": 0, "unknown": 0,
              "mod_php_present": false, "docker_containers_with_php": 0,
              "docker_affected": 0, "docker_patched": 0, "docker_unknown": 0,
              "total_targets": 0},
  "installs": [],
  "overrides": {"scanned": true, "files": []},
  "docker": [],
  "mitigation_impact": [],
  "warnings": ["…"]
}
```

**顶层没有 `tier`，没有 `verdict_reason`，没有 `confidence`。** 这三个都在 `installs[]` 的元素里（`docker[]` 带 `verdict_reason`，不带 `tier`）。

### 1.1 顶层 `verdict` —— 五个值

| 值 | `verdict_label_zh` | 含义 | `exit_code` |
|:--|:--|:--|:--:|
| `affected` | 未修 | 判定受影响 | `1` |
| `patched_with_residual` | 已修但有残留 | 版本过了，但链还通（LFI / 无 PR#22113 / 覆盖链 / 其它臂） | `0` |
| `patched_mitigated` | 已修且缓解到位 | 版本过了且缓解到位 | `0` |
| `unknown` | 判不了 | 证据不足或冲突 | `2` |
| `not_applicable` | 未发现 PHP | 没有可查对象（**不是 `unknown`，不进 unknown 占比的分母**） | `2` |

⚠️ **`patched` 不是顶层值。** 它只出现在 **install 层**（单个安装的判定）。别把两层混为一谈。

### 1.2 component 差异 —— 两形态支持的值不一样

| component | 层 | 支持的 `verdict` |
|:--|:--|:--|
| `audit.sh` | **顶层** | `affected` / `patched_with_residual` / `patched_mitigated` / `unknown` / `not_applicable`（**5 个**） |
| `audit.sh` | **install 层** | `patched` / `affected` / `unknown`（**3 个**） |
| `probe.php` | 顶层 | `affected` / `patched` / `unknown`（**3 个**） |

**这是设计差异，不是 bug**：`probe.php` 只能看到当前进程那一份配置，判不了全局，所以既不会报 `not_applicable`，也不会报 `residual` / `mitigated`。

⚠️ **写集成的人必读**：
- 拿 `probe.php` 去找 `not_applicable` → **永远找不到**
- 以为 `probe.php` 会报 `patched_with_residual` → **永远等不到**

---

## 2. 版本策略

**`schema_version` 从 `1.0` 起，只做加法。**

| 变更 | 版本动作 |
|:--|:--|
| 新增**可选**字段（如 `evidence[]`） | `1.0` → `1.1`，老消费者忽略即可 |
| 新增字段但**必填** | ❌ **禁止**（等于破坏） |
| 改字段语义 / 改类型 | `2.0`，必须附迁移表 |
| 删字段 / 改字段名 | ❌ **禁止**，只能标 `deprecated`，至少留一个大版本 |
| `reason` 词典加词 | 次版本 +1，附新旧对照 |
| `reason` 词典删词 | ❌ **禁止** |

**一句话：别人敢依赖，才叫契约。**

---

## 3. `tier` 到底在哪（最容易找错的一处）

| 位置 | 有没有 `tier` |
|:--|:--|
| 顶层 | ❌ **没有** |
| `installs[i].tier` | ✅ **有**，取值 `red` / `orange` / `yellow` / `unknown` |
| `installs[i].tier_label` | ✅ **有**（中文，如「已修但有残留」） |
| `installs[i].tier_reason` | ✅ **有**（v0.1 是中文自由文本，见 §7.2） |
| `docker[i].tier` | ❌ **没有**（v0.2 补） |

**后果，必须说清**：只跑 `--docker-only`、或 PHP 全在容器里的机器，`installs[]` 是空的，**这一轮 JSON 里就一个 `tier` 都没有**。

→ **所以 CI 判总闸一律用顶层 `verdict`，不要去找顶层 `tier`。**
→ 单机分支细节（为什么是 orange）才去看 `installs[].tier`。

---

## 4. `evidence[]`：引用式，不重复结论（`1.1` 目标）

### 4.1 为什么不另起一套

v0.1 已经有三处在装判断依据：

- `installs[].findings[]` — 结论（`id` / `severity` / `title` / `detail`）
- `overrides.files[]` — 覆盖链（`effect`）
- `mitigation_impact[]` — 三档代价（`blocks[]`）

再加一个平级的 `evidence[]` 会出现「同一件事两处说」，下游 `jq` 不知道读哪个。

**所以：结论留在原处，`evidence[]` 只补「怎么知道的」。**

### 4.2 结构

```json
{
  "ref": "installs[0].findings[3]",
  "module": "patch_composition",
  "key": "pr22113_equivalent",
  "status": "ok",
  "confidence": "verified",
  "source": "cmd",
  "locator": "/usr/share/doc/php8.5-common/changelog.Debian.gz",
  "cmd": "zgrep -i 'session fixation\\|rfc1867' /usr/share/doc/php8.5-common/changelog.Debian.gz",
  "raw": "…≤300 字符…",
  "raw_truncated": true,
  "raw_sha256": "9f2c…（对完整输出取哈希）",
  "basis": "仅 inference 时必填",
  "collected_at": "2026-10-22T13:58:20Z"
}
```

### 4.3 字段契约

| 字段 | 必填 | 类型 | 说明 |
|:--|:--:|:--|:--|
| `ref` | ✅ | string | **指回原结构**，如 `installs[0].findings[3]`、`overrides.files[2]`、`mitigation_impact[1]`；顶层结论用 `top` |
| `module` | ✅ | enum | `version` / `patch_composition` / `coverage_chain` |
| `key` | ✅ | string | 机器可读键名 |
| `status` | ✅ | enum | `ok` / `unknown` / `error` |
| `confidence` | ✅ | enum | `verified` / `static_only` / `inferred` |
| `source` | ✅ | enum | `cmd` / `file` / `probe` / `changelog` / `source_tree` / `inference` |
| `locator` | ⬜ | string | 文件路径 / 位置 |
| `cmd` | ⬜ | string | **可粘贴复跑** |
| `raw` | ⬜ | string | 原始输出片段，≤300 字符 |
| `raw_truncated` | ✅ | bool | 是否截断（**必填，不许默认 false**） |
| `raw_sha256` | ⬜ | string | 完整输出哈希（见 §5） |
| `basis` | ⬜ | string | **`source=inference` 时必填** |
| `collected_at` | ✅ | ISO8601 | 采集时刻 |

**注意**：`evidence[]` 里**没有** `value` / `claim` / `id` —— 那些在 `ref` 指的地方。**这条是「不重复结论」的落地。**

---

## 5. `raw` + `raw_sha256`

- `raw` 保持 **≤300 字符**：够人看，够 `jq` 显示
- **`raw_sha256`**：对**完整**输出取 SHA-256

**怎么用**：客户拿到 `raw` 片段 + `raw_sha256`，自己跑一遍 `cmd`，对完整输出算哈希 ——
**对得上 = 没篡改；对不上 = 有问题。**

比「给你看 300 字」强一个档：**截断了也验得了。**

⚠️ **哈希的输入定义必须写死**（是否含结尾换行、是否 UTF-8 规范化），否则同一命令在不同环境哈希不同，验证就废了。约定：`LC_ALL=C`，保留原始字节，不规范化换行。

---

## 6. 退出码契约（永不改）

**脚本第一件事就是 `if [ $? -eq 1 ]`。这个变了，所有集成全断。**

| 退出码 | 对应 `verdict` | 含义 |
|:--:|:--|:--|
| `0` | `patched_with_residual` | **版本这条轴过了，但链还通** —— 需人看一眼 |
| `0` | `patched_mitigated` | 已修且缓解到位 —— 真过关 |
| `1` | `affected` | 受影响 |
| `2` | `unknown` / `not_applicable` | 无法判定 / 没有可查对象 |
| `3` | —（工具自身） | 参数错、权限不足、临时目录建不了 |

**这四个码的语义永不改变。** 新增语义只能加新码（如 `4`），不能复用旧码。

### ⚠️ `exit 0` 不等于「安全」

**`exit 0` 同时覆盖两档，而这两档风险差一个数量级：**

| 组合 | 含义 | CI 该怎么办 |
|:--|:--|:--|
| `exit 0` + `patched_mitigated` | 真过关 | 放行 |
| `exit 0` + `patched_with_residual` | **链子还通** | **不能放行**，要人看一眼 |

CI 作者的第一反应是 `if [ $? -eq 0 ]; then pass` —— **那会放行一批「链子还通」的机器。**

另外：**`exit 0` 只代表「版本层面已修」，不代表应用层没有 LFI，也不代表全站安全。** 集成方不得拿 `exit 0` 去做安全判断。

---

## 7. `reason`：两本词典，别混成一本

### 7.0 位置：都不在顶层

`verdict_reason` 和 `tier_reason` 都在 **`installs[]` 的每个元素里**；`docker[]` 的元素带 `verdict_reason`，不带 `tier_reason`。

**写集成的人别在 `. | jq .verdict_reason` 上找** —— 那是空。

### 7.1 `verdict_reason` —— 枚举，实测 **9** 个，三个来源

```bash
# 来源 A：classify_version() 用 printf 返回（不带 reason=，grep reason= 抓不到）
audit.sh:206  printf 'patched\tversion_at_or_above_branch_fix:%s\n' "$fix"
audit.sh:209  printf 'patched\tversion_below_affected_range\n'
audit.sh:212  printf 'affected\tversion_in_vulnerable_range\n'
audit.sh:214  printf 'unknown\tversion_above_advisory_range:%s\n' "$v"

# 来源 B：collect_install() 覆写
audit.sh:1220  reason='backport_marker_present'
audit.sh:1224  reason='conflicting_evidence_changelog_says_patched_binary_lacks_marker'
audit.sh:1226  reason='package_changelog_mentions_cve'
audit.sh:1231  reason='backport_marker_present_and_changelog_confirms'

# 来源 C：docker_verdict()
audit.sh:1115  printf 'unknown\tcontainer_php_version_unparseable'
```

| # | 值 | 含义 |
|:--:|:--|:--|
| 1 | `version_at_or_above_branch_fix` | 版本在同分支修复线以上（**带 `fix_version`**） |
| 2 | `version_below_affected_range` | 版本低于受影响区间 |
| 3 | `version_in_vulnerable_range` | 版本在受影响区间内 |
| 4 | `version_above_advisory_range` | 版本高于公告区间，判不了（**带 `observed_version`**） |
| 5 | `backport_marker_present` | 二进制里找到补丁符号 |
| 6 | `package_changelog_mentions_cve` | 包 changelog 提到该 CVE |
| 7 | `backport_marker_present_and_changelog_confirms` | 两者都有 |
| 8 | `conflicting_evidence_changelog_says_patched_binary_lacks_marker` | **证据冲突**：包说修了、二进制说没修 → 不猜 |
| 9 | `container_php_version_unparseable` | 容器里的版本解不开 |

### 7.1.1 三条带变量的，必须拆伴生字段

v0.1 实际输出形如 `version_at_or_above_branch_fix:8.5.12` —— **那个 `8.5.12` 就是「已修」的直接依据。**

只当枚举会丢掉它，等于证据里最硬的一条变成「差不多修了」。

| 枚举值 | 必带伴生字段 | 类型 | 示例 |
|:--|:--|:--|:--|
| `version_at_or_above_branch_fix` | `fix_version` | string | `"8.5.12"` |
| `version_above_advisory_range` | `observed_version` | string | `"8.6.0"` |
| `tier_reason=override_weakens` | `override_weak_count` | int | `3` |

**规则一句话：枚举值里不许内嵌变量；凡是要带数字的，一律拆成伴生字段。**

### 7.2 `tier_reason` —— v0.1 是自由中文，v0.2 转枚举

v0.1 实际是 10 条中文自由文本（`audit.sh:1072–1092`）：

| v0.1 中文原文 | v0.2 枚举键 | 备注 |
|:--|:--|:--|
| 版本无法对照公告区间 | `version_unparseable` | |
| 版本在受影响区间且无 backport 证据 | `affected_no_backport` | `tier=red` |
| 版本已修，但站点存在 LFI 落点… | `lfi_sink_found` | |
| …无 PR#22113 等价修复… | `pr22113_absent` | |
| 覆盖链里有 `${ovr_weak}` 条会重新削弱缓解措施 | `override_weakens` | ⚠️ **带变量，配 `override_weak_count`** |
| 8.5.x 上 `fatal_error_backtraces` 仍为开 | `fatal_backtraces_on` | |
| OPcache 开着且补丁标记缺失 | `opcache_needs_patch` | |
| LFI 落点未检查（`--no-scan`）… | `lfi_not_scanned` | |
| 版本已修 + 无 LFI 落点 + PR#22113 等价 + 缓解到位 | `all_clear` | `tier=yellow` |
| 判定异常 | `internal_error` | |

**拆分方案**：

| 字段 | 用途 | 类型 |
|:--|:--|:--|
| `tier_reason` | 统计用 | ✅ **枚举**（上表 10 个键） |
| `tier_reason_text` | 展示用 | ⬜ 自由中文，**不参与统计** |

### 7.3 为什么必须转

下游要回答「这批机器里残留原因分布是什么」，v0.1 只能对中文做正则 —— **换一版文案，统计就断。**

而 `patched_with_residual` 恰好是最需要被统计的一档：**它是「版本过了但链还通」，是我们唯一能证明「比版本号扫描器多看见一层」的地方。** 这一档的原因分布，就是产品价值证据。

---

## 8. 三条硬规则

1. **`status != ok` 不得被解读为「安全」。** 写进 schema，也写进 README 首屏。
2. **`source=inference` 必须带 `basis`。** 例如「上游 PR 未合入 ⇒ 官方包默认 absent」，依据要写出来。
3. **`raw_truncated` 必填。** 截断了还装作完整，就是给复跑的人挖坑。

---

## 9. 下游怎么用

**现在就能跑的（v0.1）：**

```bash
# 总闸
./audit.sh --json | jq -r '.verdict'

# 单机分支细节（注意：只在 installs[] 里）
./audit.sh --json | jq '.installs[] | {binary, verdict, tier, tier_label}'

# 结论清单
./audit.sh --json | jq '.installs[].findings[] | {id, severity, title}'

# 容器里的
./audit.sh --json | jq '.docker[] | {image, verdict, verdict_reason}'
```

**`1.1` 之后才能跑的：**

```bash
# 证据
./audit.sh --json | jq '.evidence[] | {ref, cmd, raw, raw_sha256}'

# 判不了的
./audit.sh --json | jq '.evidence[] | select(.status=="unknown") | {ref, key, reason}'

# 验证某条证据没被篡改
./audit.sh --json | jq -r '.evidence[3].cmd' | bash 2>&1 | sha256sum
# 与 .evidence[3].raw_sha256 比对
```

---

## 10. 这份东西为什么是护城河

功能会被抄（一天 8 个 nuclei 模板）。**但没人会抄一个别人已经集成的输出格式。**

一旦托管商把 JSON 接进面板、审计师按 `evidence[]` 取证、别人的脚本开始 `jq .evidence[].cmd` ——
**格式就成了迁移成本。**

**而这份契约的可信度，取决于它第一天写得多实。** 所以本文档宁可承认「`evidence[]` 现在没有」。

---

## 11. 修订记录

| 日期 | 改了什么 | 为什么 |
|:--|:--|:--|
| 2026-10-22 | 首版落仓 | — |

**写作时踩过、已修正的四处（留档，防复发）：**

| 错 | 表现 | 修法 |
|:--|:--|:--|
| `lfi_exposure` | 写了个 v0.1 不存在的字段 | 删；README 改成「v0.1 不检测 LFI」显式说明 |
| `16 checks` | 帖子写 16，实际 31 PASS | 现数，不抄旧值 |
| 14 个 `reason` 词 | 从设计稿抄的，代码 0/14 命中 | 全部重数，换成实测 9 个 + 10 个 |
| `tier` 位置 | README 教人看顶层 `tier`，顶层没有 | 改成看顶层 `verdict`；`tier` 只作单机细节 |

> **教训：** 字段名错了程序会报错，**枚举词错了程序照常跑，只是永远匹配不上。**
> 而「数了一遍」不等于「数对了」——只在一种语法形态里 grep，会得到一个看起来精确的错误答案。

---

_php-exposure-audit · 输出契约 · 2026-10-22_
