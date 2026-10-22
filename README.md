# php-exposure-audit

**PHP 暴露面自查 · MVP v0.1.0** — 针对 CVE-2026-109618 / CVE-2026-109619（CVSS 9.2）。

扫描器市面上有一堆，免费开源、够用的也有。这个的区别只有一句：

> **别人告诉你「你有洞」，我们告诉你「这个包到底修了什么，以及你怎么自己复核」。**

两件事撑着这句话：

- **「补了洞，链子还通不通」** — 这才是要回答的问题。版本号只是七条轴里的一条：`version` / `patch_composition` / `upload_progress` / `lfi_exposure` / `serializer_reset` / `fatal_error_backtraces` / `opcache`，每项独立检查、独立输出，最后聚合成三档。**版本达标但链子还通，就报 🟠 已修但有残留，不报「安全」。**
- **「怎么复核」** — 报告里每条结论都带来源、命令和原始输出。你能自己重跑一遍，也能直接拿给老板或客户看。

**这是判断工具，不是防护工具。** 它不改配置、不写 drop-in、不重启服务。它只回答三件事：**中没中、为什么这么判、下一步该干什么。** 防护动作留给人。

- 只读，不写配置、不改文件、不发外部请求
- 不做外部扫描、不含利用代码
- 判不了就报 `unknown`，不猜；一个 PHP 都没找到时报 `not_applicable`，绝不当成「安全」

---

## 这个 CVE 到底要查什么

公告说的是「PHP 5.4.0–8.5.11 全部受影响」，但**光看 `php -v` 的数字会判错两次**，两个方向都会错：

1. **版本号旧但发行版已 backport** — Debian/Ubuntu/RHEL 经常把安全补丁打回旧版本号。`8.2.30-1+deb12u3` 这种包，数字在受影响区间里，实际已经修好了。
2. **版本号新但没打这个补丁** — 自己编译的、面板自带的、镜像里冻住的，数字过了线也不一定有补丁。

所以工具不靠单一证据。判定用三条独立证据交叉：

| 证据 | 怎么拿 | 能证明什么 |
| --- | --- | --- |
| 版本区间 | `PHP_VERSION` vs 各分支修复线 | 必要条件，不充分 |
| 发行版 changelog | dpkg / rpm 的 changelog 里有没有提这两个 CVE | 包维护者声称已修 |
| 二进制 patch 标记 | 二进制里有没有 `php_basic_early_rinit` / `zend_handle_delayed_oom` | 代码里真的打了补丁（最强证据） |

**冲突时一律 `unknown`。** 比如 changelog 说修了、但二进制里确实没有补丁符号 —— 这种包是被 strip 过、或者是错版，工具不会替你选一个答案。

### 但版本只是七条轴里的一条

上面那三条证据只回答「OOM 那条修了没」。**Chain A 的写原语是设计如此，修不了；session fixation 守卫的 PR 至今没合。** 只看版本会得出「版本够新 = 安全」的错误结论。

所以判定拆成七条独立轴，每项单独输出、谁也盖不过谁：

| 轴 | 看什么 | 不过是什么样 |
| --- | --- | --- |
| `version` | ≥8.2.35 / 8.3.36 / 8.4.27 / 8.5.12，或发行版 changelog 含 CVE 号 | `affected` |
| `patch_composition` | **有没有 PR#22113 等价修复**（distro backport 常只含 OOM 那条） | `pr22113_absent` |
| `upload_progress` | `session.upload_progress.enabled` 开 or 关（开着 = 写原语在） | `enabled` |
| `lfi_exposure` | webroot 里有没有 LFI 落点（**有 = Chain A 可打，与版本无关**） | `sink_found` |
| `serializer_reset` | FPM 跨请求是否还泄漏残留状态 | `leaks` |
| `fatal_error_backtraces` | 仅 8.5.x，须为 0 | `on` |
| `opcache` | 启用则需补丁覆盖 | `needs_patch` |

**`patch_composition` 怎么判（不猜）：**

- 只在两种情况下给确定答案：changelog 里明确提到 session fixation / rfc1867 / 22113 / use_only_cookies → `pr22113_present`；是上游官方修复版（已知不含该 PR）→ `pr22113_absent`
- 其余一律 `unknown` + 说明为什么（changelog 不可读 / 自编译无包信息），**绝不默认成「已修」**

七轴聚合出三档：

| 档 | 条件 |
| --- | --- |
| 🔴 未修 | `version` 轴不过（受影响区间且无 backport 证据） |
| 🟠 已修但有残留 | 版本过了，但：有 LFI 落点 / 无 PR#22113 等价 / 覆盖链有 weakens / 8.5.x 的 backtraces 还开着 / OPcache 需补丁 |
| 🟡 已修且缓解到位 | 上面全清 |

**LFI 落点的扫法**：直接式 `include $_GET['tpl'];` 和间接式 `$tpl = $_GET['tpl']; include $tpl;` 都抓 —— 间接式才是真实代码里最常见的写法，只抓直接式会大量漏报，而漏报在这个工具里是最坏的错误。

`php_basic_early_rinit` 是补丁 [3584a98](https://github.com/php/php-src/commit/3584a98bda) 新增的符号，出现在二进制里就说明源码树是打过补丁的。为了区分「没补丁」和「被 strip 了」，同时找 `php_request_shutdown` 这个任何正常 PHP 二进制都有的符号当对照组：

- 有 patch 符号 → `present`
- 没 patch 符号，但有对照符号 → `absent_conclusive`（**确定**没打补丁）
- 两个都没有 → `inconclusive`（strip 了 / 读不到 / open_basedir 挡住），**标记缺失不能当证据**

---

## 一个容易被误读的点

**升级到修复版，不代表所有攻击面都关了。**

这次补丁修的是 OOM 处理和启动期的残留状态。但 `session.upload_progress` 把上传文件名原样写进 session 文件，**是既有设计，不是漏洞**——它配合应用自身的 LFI 落点仍然能走通。

所以：

- **版本这一项判 `patched`，只说明 PHP 引擎层的那条路堵上了**
- **它不说明你的应用没有 LFI**，也不说明你该停在这里
- 这部分**责任在应用层**，不在 PHP 版本号上

工具**不会拿一个 `patched` 把后面的风险盖掉**：报告里会单独提一行，提醒你引擎层已修但应用层仍需自查。

⚠️ **v0.1 不检测 LFI**——这一项在 v0.2 的计划里。所以如果你看到 `patched`，正确读法是「**PHP 那块查清了，应用那块还没查**」，不是「全站安全」。

---

## 两种形态，什么时候用哪个

### `probe.php` — 放进 webroot，走 HTTP

**适用**：你只能通过网络碰到这台机器（客户站点、托管主机、SaaS 平台、只给你一个 FTP/面板的虚拟主机）。判断的是**真实在跑的那个 PHP 进程**——不是磁盘上装了哪个版本。

```bash
# 1. 上传到 webroot
scp probe.php user@host:/var/www/html/

# 2. 配令牌（三选一，按优先级）
export PHP_EXPOSURE_AUDIT_TOKEN='<长随机串>'      # 方式一：环境变量
echo -n '<长随机串>' > /var/www/html/.audit-token  # 方式二：同目录文件（推荐）
# 方式三：PHP_EXPOSURE_AUDIT_TOKEN_FILE=/etc/pea.token

# 3. 取报告
curl -s -H "Authorization: Bearer $TOKEN" 'https://host/probe.php?format=json' | jq .
curl -s -H "Authorization: Bearer $TOKEN" 'https://host/probe.php?format=html' > report.html
```

**令牌与 404**

无令牌、错令牌、没配令牌 —— 三种情况都返回 **404**，body 和 Apache 默认 404 一模一样（159 字节，同样的 `<h1>Not Found</h1>`）。别人扫到这个路径也看不出这里有东西。

⚠️ **`Authorization` 头在 mod_php 下会被吞掉。** Apache 默认不会把 `Authorization` 传进 `$_SERVER`（除非显式 `CGIPassAuth On`）。工具用 `getallheaders()` 兜住了，但更稳的做法是直接用 `X-Audit-Token`：

```bash
curl -H "X-Audit-Token: $TOKEN" 'https://host/probe.php?format=json'
```

调试期可以用 `?token=...`，但**会写进访问日志**，工具会在 `warnings` 里提醒你。

**用完要删。** 工具没法自己删自己（没有写权限是好事），但你应该在拿到报告后立刻 `rm`。

⚠️ **文件权限必须是 644。** `probe.php` 如果是 `0600`（比如你用 `scp -p` 传的），Apache 的 worker 用户读不到它，会返回 **HTTP 200 + 一段 PHP Fatal error 页**，而不是 404 也不是正常报告。这时候只看状态码会以为「通了」。上传后先 `chmod 644 probe.php`。

### `audit.sh` — 本机或 ssh 跑

**适用**：你能登进机器。可以看全机器上**所有** PHP 安装（可能装了 5 个），能看到包管理器、changelog、所有 SAPI、所有 ini 变体。

```bash
# 本机
./audit.sh

# 远程，不拷文件
ssh host 'bash -s' < audit.sh

# 指定 webroot
./audit.sh --root /data/www --root /srv/apps

# 机器上跑着一堆 docker 容器
./audit.sh              # 默认会连 docker 一起查
./audit.sh --docker-only
./audit.sh --no-docker  # 完全不碰 docker

# 管道
./audit.sh --json | jq .verdict
```

会扫到这些地方：

- PATH 里的 `php` / `php5` / `php7` / `php8` / `php-cgi` / `php-fpm` / `lsphp` / `frankenphp`
- `/usr/bin`、`/usr/local/bin`、`/opt/cpanel/ea-php*/root`、`/opt/remi/php*/root`、`/opt/alt/php*`
- `/www/server/php/*`（宝塔）、`/usr/local/php*`（oneinstack/lnmp）、`/usr/local/lsws/lsphp*`（LiteSpeed）
- Homebrew（`/opt/homebrew`）、MAMP
- 有界 `find` 兜底（`/opt /usr/local /www /home /srv`，最多 5 层）
- docker：所有运行中的容器，`docker exec` 进去问，拿到版本后**同样参与判定**（不是只列出来）

### 覆盖链 — 这一块是差异化

NCSC 的 cPanel 脚本专门扫 `/home` 下的 `.htaccess` / `.user.ini` / `php.ini`，因为它们**能把你刚写进 drop-in 的缓解措施又打开**。别人做暴露面检测通常不做这一步。

`audit.sh` 扫这些目录：

```
/var/www/html  /var/www  /usr/share/nginx/html  /srv/www  /data/www
/www/wwwroot/*  /home/*/public_html  /var/www/vhosts/*/httpdocs
apache2ctl -S 里的 DocumentRoot     nginx 配置里的 root
```

每个文件里抓 `php_value` / `php_flag` / `php_admin_value` / `php_admin_flag`，以及裸的 `key = value`，只看关注的那 9 个键。每条给一个 `effect`：

| effect | 含义 |
| --- | --- |
| `weakens` | 把 `session.upload_progress.enabled` 或 `fatal_error_backtraces` 重新打开了 ← **要处理** |
| `raises` | 抬高了 `post_max_size` / `upload_max_filesize` / `memory_limit` |
| `neutral` | 跟这两个 CVE 无关 |
| `ok` | 明确关掉了 |

`probe.php` 分两类报：`applies_to_me: true`（当前脚本所在目录及其祖先，这些真的作用在本进程上）和 `false`（文档根下的旁路目录，不影响本次请求但说明全站有覆盖）。

---

## 输出契约

### 人类可读：先结论后细节

**第一行必须是三档之一：`未修` / `已修但有残留` / `已修且缓解到位`。第二行是该做什么。** 这两行在 24 行终端里也能看见，后面的细节是给要深挖的人看的。

```
已修但有残留
版本已修，但站点存在 LFI 落点 —— Chain A 可打，与版本无关。补丁修的是 OOM 和残留状态；upload_progress 的文件名写入是设计如此，配任何应用层 LFI 链子就通，责任在应用层。

----------------------------------------------------------------
php-exposure-audit v0.1.0   CVE-2026-109618 / CVE-2026-109619 (CVSS 9.2)
...
--- [1/1] PHP 8.5.12   /usr/local/bin/php ---
结论        : 已修但有残留
原因        : 版本已修，但站点存在 LFI 落点 —— Chain A 可打，与版本无关
七轴检查    :
  ok version                  patched          8.5.12
  !! patch_composition        pr22113_absent   PR#22113 未合并，源码里没有 session fixation 守卫
  !! upload_progress          enabled          session.upload_progress.enabled=1
  !! lfi_exposure             sink_found       2 处可疑 include/文件读取
  ok serializer_reset         not_applicable   当前 SAPI 不是 FPM
  !! fatal_error_backtraces   on               8.5.x 须为 0
  ok opcache                  covered          补丁标记在
```

⚠️ **绝不说「版本已修 = 安全」。** 版本那一格是 `patched`、整体却是橙色，这就是「补了洞，链子还通」的样子。

### JSON：稳定 schema，snake_case

```jsonc
{
  "schema_version": "1.0",
  "tool": { "name": "php-exposure-audit", "component": "audit.sh", "version": "0.1.0" },
  "generated_at": "2026-10-22T07:45:30Z",
  "host": { "hostname": "...", "os": "Linux", "kernel": "..." },

  "verdict": "patched_with_residual",   // 见下表
  "verdict_label_zh": "已修但有残留",
  "verdict_reason": "version_in_vulnerable_range",
  "confidence": "high",
  "exit_code": 0,
  "action": "...",

  // 三档判定由七轴聚合而来。每台机器报各自的 tier，顶层报最坏的那一档。
  "tier": "orange",                  // red | orange | yellow | unknown
  "tier_label": "已修但有残留",
  "tier_reason": "版本已修，但站点存在 LFI 落点 —— Chain A 可打，与版本无关",

  // 这次到底查到东西没有。0 = 一个 PHP 目标都没找到，
  // 此时 verdict 必然是 not_applicable、退出码 2。
  // 调用方先看这个字段，就不用去数 installs 数组。
  "targets_found": 1,               // 宿主机安装数 + 容器里带 PHP 的容器数

  "installs": [                     // 每个 PHP 安装一条
    {
      "binary": "/usr/local/bin/php",
      "binary_real": "/usr/local/bin/php",
      "version": "8.5.11",
      "version_branch": "8.5",
      "cli_sapi": "cli",
      "zend_version": "4.5.11",
      "build_date": "Oct 21 2026 00:26:24",
      "package": { "manager": "none|dpkg|rpm", "name": "", "version": "" },
      "verdict": "affected",
      "verdict_reason": "version_in_vulnerable_range",
      "confidence": "high",
      "backport": {
        "marker_state": "absent_conclusive",   // present | absent_conclusive | inconclusive
        "package_changelog": ""
      },
      "sapis": { "available": "apache2handler", "active": "apache2handler", "mod_php": 1 },
      "ini": {
        "session.upload_progress.enabled": { "value": "1", "source": "generic:/usr/local/etc/php/php.ini" }
      },
      "ini_sources": [ { "sapi": "generic", "ini_file": "/usr/local/etc/php/php.ini", "scan_dir": "/usr/local/etc/php/conf.d" } ],
      "notes": ["mod_php 已加载：..."],
      "findings": [ { "id": "sapi.mod_php", "severity": "critical", "title": "...", "detail": "..." } ]
    }
  ],

  "overrides": {
    "scanned": true,
    "files": [ { "file": "...", "line": 4, "directive": "php_flag session.upload_progress.enabled On", "effect": "weakens" } ]
  },

  "docker": [
    {
      "id": "93fe50a7ba7a",
      "image": "php:8.5.11-apache",
      "version": "8.5.11",
      "verdict": "affected",
      "verdict_reason": "version_in_vulnerable_range",
      "facts": { "BIN": "/usr/local/bin/php", "VER": "8.5.11", "SAPI": "cli", "MODPHP": "1", "MARKER": "absent" }
    }
  ],
  "warnings": []
}
```

容器里的 PHP 也进 `summary` 计数，并且**参与总判定**：只要有一个容器是 `affected`，整体就是 `1`。`summary` 里 `affected/patched/unknown` 只算宿主机上的安装，容器单独一组（`docker_affected` / `docker_patched` / `docker_unknown`），`total_targets` 是两边加起来。

`probe.php` 用同一份 schema，区别是：`tool.component` 为 `probe.php`、有 `mode: "probe"`、`runtime` 换成这次的请求上下文、没有 `installs` 数组（它只报告自己这一个进程）。

`ini` 一项两边结构不同，这是故意的：

```jsonc
// audit.sh —— 多个 SAPI 各自一份 php.ini，所以要标明来源
"ini": { "session.upload_progress.enabled": { "value": "1", "source": "generic:/usr/local/etc/php/php.ini" } }

// probe.php —— 只有一个进程，但能看出是否被 per-directory 改过
"ini": {
  "session.upload_progress.enabled": {
    "value": "1", "global_value": "1", "local_value": "1",
    "access": 4, "overridden": false, "state": "weak", "advice": "0"
  }
}
```

`state` 是 `ok | weak | info`，`weak` 表示这一项把攻击面留着了。`overridden` 为 `true` 说明被 `.user.ini` / `.htaccess` 改过（`local_value` ≠ `global_value`）。

### 退出码

| 码 | 含义 |
| --- | --- |
| `0` | `已修且有残留` 或 `已修且缓解到位` |
| `1` | `未修` |
| `2` | 判不了（含「一个 PHP 都没找到」→ `not_applicable`） |
| `3` | 工具自身出错（参数错、临时目录建不了） |

一台机器上装了多个 PHP 时按最坏档取：red > orange > unknown > yellow。容器里的 PHP 也算。

**「已修但有残留」退出码是 0，这是刻意的。** 它表示「版本这条轴过了」，不是「安全」。CI 里别拿退出码当放行依据，要看 `tier`。

---

## 局限 —— 什么时候会「判不了」

工具报 `unknown` 的每一种情况，以及为什么：

### 1. 版本在公告区间之上，但对照不了

`8.6.0`、或者某个厂商自己编的 `8.5.11-custom`。公告只写到 8.5.11，之后的分支修没修、怎么修的，工具不知道。**报 unknown，不猜。**

### 2. 二进制被 strip，且没有包管理器证据

`strip` 过的 PHP、删了符号的镜像、`open_basedir` 挡住读不到文件 —— 此时 patch 标记拿不到。如果版本落在受影响区间里，工具仍然报 `affected`（版本是硬证据），但 `confidence` 降到 `medium` 并在 `warnings` 里说明。只有在版本本身就判不出来的时候才会变成 `unknown`。

### 3. changelog 说修了，二进制说没修

分发版把 patch 打上了但没重新编译干净、或者构建流程出错 —— 这种「错版包」真的存在。两条证据打架时**不选边**，报 `unknown` 并写明冲突原因。

### 4. `probe.php` 看不到全局

只能看到**当前进程**加载的那一个 PHP。同机器上另外三个 FPM 池、另一个版本的 cgi、命令行用的那个 PHP —— 一个都看不到。**要全貌就用 `audit.sh`。**

### 5. `audit.sh` 的结构性盲区

- **非 Linux**（macOS/BSD）：没有 `/proc`，看不到进程 maps，所以判不了「mod_php 是否正在被加载」，只能报「有 libphp.so」。`active` 列表用 `ps -eo comm`，精度下降。
- **容器里跑 `audit.sh`**：只看得到这个容器里的 PHP，看不到宿主机和其他容器。要查全部就在宿主机上跑。
- **docker 容器不是 Linux 或没有 shell**：`docker exec` 失败，静默跳过，只计入总数不算判定；同时在 `warnings` 里说明「docker 不可用或没有运行中的容器」。
- **一个 PHP 都没找到**：报 `not_applicable`（标签「未发现 PHP」）+ 退出码 `2`，不是「不中」。找不到 ≠ 安全 —— 可能 PHP 跑在别的用户目录、另一个容器、或者压根不是 PHP 站点。
  ⚠️ 它与 `unknown` 的退出码相同，但 **verdict 值不同**：`not_applicable` = 本次什么都没查到，`unknown` = 查到了但判不明白。机器读 JSON 时能分开，别把两个混着处理。
- **webroot 位置完全自定义**（比如 `/opt/apps/xxx/public`）：自动发现找不到。用 `--root` 显式指定。
- **覆盖链最多扫 40 个根、2 万文件、6 层深**：超大主机可能漏掉深处的 `.htaccess`。
- **`.htaccess` 是否真的生效**：工具只报「文件里有这条指令」，不判断 `AllowOverride` 允不允许它生效。apache `AllowOverride None` 下的 `.htaccess` 是死文件，但工具照样会列出来 —— 这一条需要你自己看 `apache2ctl -S`。

### 6. 「版本已修」绝不等于安全

**Chain A（session 注入 + 应用 LFI）在 8.5.12 上依然能用。** 补丁修的是 OOM 破坏和跨请求脏状态，没有把「文件名原样存进 session 文件」这个设计改掉 —— 对 PHP 来说那是 feature，不是 bug。

源码级证据（php-8.5.12，`ext/session/session.c`）：

```c
// 第 3322 行：写原语没被动过，无净化、无长度限制
add_assoc_string_ex(&progress->current_file, ZEND_STRL("name"), *data->filename);

// 约 3268 行，rfc1867 的 FORMDATA 分支：session fixation 守卫不存在
// 前面没有 !PS(use_only_cookies)
if (zend_string_equals_cstr(PS(session_name), data->name, name_len)) {
```

全文件 `!PS(use_only_cookies)` 只在 101 / 1732 / 1747 三行，**不在 rfc1867 分支**。对应的 PR #22113 至今 `state: open` / `merged: false`，8.5.12 里没有它。

所以：

- `version` 轴 `patched` = 这两个 CVE 的 **OOM / 残留状态**在引擎层面已修
- `version` 轴 `patched` ≠ 你的应用没有 LFI、≠ 文件上传安全、≠ session fixation 有守卫

工具会把这两件事分开报：`version` 是 `patched`、但 `lfi_exposure` 是 `sink_found`，整体就是 🟠 **已修但有残留**。不管什么时候，都不许把「版本够了」当成结论。

---

## 判定之后该做什么

完整修复只有一条：**升级**。

| 现状 | 该做什么 |
| --- | --- |
| `affected`，有官方修复版 | 升到 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12（按你现在的分支） |
| `affected`，8.0/8.1（EOL） | 升大版本；或上社区 backport（[Anton-Barinov/php2shell-patches](https://github.com/Anton-Barinov/php2shell-patches)，非官方） |
| `affected`，5.x–7.4 | **没有官方修复，也没有可靠 backport。** 只能升大版本 |
| `affected`，暂时升不了 | 见下面的缓解措施 —— 能降风险，**不能替代升级** |
| `patched` | 保持自动安全更新；检查覆盖链里有没有 `weakens` |
| `unknown` | 拿包管理器版本 + 发行版安全公告人工确认。**别当安全处理** |
| `not_applicable` | 本机没扫到 PHP。若 PHP 跑在容器 / 别的机器 / 自定义路径，加 `--root` 或 `--docker-only` 重跑。**别当安全处理** |

### 缓解措施（升级前的临时手段）

```ini
; 能用，但都不是修复
session.upload_progress.enabled = 0    ; 砍掉 CVE-2026-109619 的会话注入面
fatal_error_backtraces = 0             ; 8.5 分支特有，第三条臂
memory_limit = -1                      ; 反直觉：去掉可预测的 OOM 触发点
```

⚠️ **`session.upload_progress.enabled=0` 挡不住 CVE-2026-109618。** OOM 破坏在 Zend 引擎核心里，任何一个超大 multipart POST 都能触发，跟 upload_progress 无关。PHP 核心开发者明确说过不要拿这一条当修复。

⚠️ **不要用 `RLimitMEM` / `RLIMIT_AS` / `RLIMIT_DATA` 来限内存。** 那会让 `mmap` 失败，正好走进同一条漏洞路径。

⚠️ 关掉之后记得回头查 `overrides` —— 站点里的 `.htaccess` 会把 `upload_progress` 又打开。

### 三档处置的代价（`mitigation_impact`）

只告诉人「你中招了」不够用。工具还会算清**三条路各废什么**，写在 JSON 的 `mitigation_impact` 和人类报告的「处置选项」段里：

| 档 | 要报什么 |
| --- | --- |
| **A. 升级 PHP** | 当前版本 → 目标版本；EOL 分支（5.x–8.1）报「必须升到 8.2.35+ 之一」 |
| **B. Web 层 403 multipart** | **扫出会被打废的具体功能**：`<form enctype="multipart/form-data">`、常见上传接口路径、WP 媒体库、后台附件。每条带文件、行号、猜的用途、原始片段 |
| **C. 只关 `session.upload_progress`** | 明确写「只治 109619 的 session 路径，**对 109618 无效**」—— 别让人误以为这是完整修复 |

B 档**只读文件系统**，不发任何请求、不触发漏洞路径。猜不出用途就写「疑似上传」，不编造功能名。上限 `MP_MAX_FILES`（默认 3000，probe 里是 `PEA_MP_MAX_FILES`=1500），超了报「扫描被截断」。

两个形态输出**同一形状**——都是站点数组，probe 里永远只有一项：

```jsonc
"mitigation_impact": [
  {
    "site": "/var/www/html",
    "forms_found": 4,
    "endpoints_suspected": 0,
    "options": [
      {
        "id": "upgrade_php",
        "title": "升级 PHP",
        "cost": "low",
        "from_version": "8.5.11",
        "to_version": "8.5.12",
        "note": "升级到同分支修复版；不改代码、不改配置。",
        "blocks": [],
        "notes": ["不改代码、不改配置", "唯一完整修复"]
      },
      {
        "id": "block_multipart",
        "title": "Web 层 403 multipart",
        "cost": "high",            // 有表单就是 high，没有才是 low
        "blocks": [
          {
            "file": "/var/www/html/shop/product-edit.php",
            "line": 1,
            "kind": "form_multipart",   // form_multipart | input_file | formdata_js | wp_media
            "confidence": "high",       // high | medium | low
            "purpose": "商品图上传",     // 猜的；猜不出写「疑似上传…」
            "evidence": "<form action=\"/admin/save.php\" method=\"post\" enctype=\"multipart/form-data\">"
          }
        ],
        "suspected_endpoints": [],
        "limitation": null,          // 判不了时写明原因
        "notes": ["不发起任何请求，只读文件"]
      },
      {
        "id": "disable_upload_progress",
        "title": "只关 session.upload_progress",
        "cost": "low",
        "covers": ["CVE-2026-109619 的 session 注入路径"],
        "does_not_cover": ["CVE-2026-109618（Zend 引擎 OOM，与 upload_progress 无关）"],
        "blocks": [],
        "notes": ["不是完整修复"]
      }
    ]
  }
]
```

`cost` 是给程序读的粗判：`low` = 升级或关开关这类不影响功能的；`high` = 会打废功能的。B 档在找到表单时一定是 `high`，一个都没找到时是 `low` 并在 `limitation` 里说明为什么可能漏。

probe 的 `block_multipart` 额外带 `scanned_files` 和 `truncated` 两个字段（它只有一个 docroot，需要让人知道扫了多少）。

---

## 靶场与自测

`lab/` 下是可以复跑的验证环境。**只在本机跑，不对外暴露。**

```bash
cd lab
export PEA_TOKEN="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
echo "$PEA_TOKEN" > .pea-token
docker-compose up -d

./selftest.sh            # 期望 31 PASS / 0 FAIL
docker-compose down -v
```

两个容器：`pea-lab-vuln`（8.5.11，端口 18091，期望 `affected`）和 `pea-lab-fixed`（8.5.12，端口 18092，期望 `patched`）。同一份 `php.ini`、同一个 webroot，唯一变量是 PHP 版本。

webroot 里故意放了两个覆盖链样本：`legacy/.htaccess`（`php_flag` 语法，把 upload_progress 打开）和 `uploads/.user.ini`（`key = value` 语法）。工具必须都能抓出来。

实际跑出来的完整终端输出在 **[`SELF-TEST.md`](SELF-TEST.md)**。

---

## 设计取舍

**为什么 `probe.php` 要兼容 5.x？** 受影响区间下界就是 5.4.0。工具如果只能在 8.x 上跑，那最需要它的机器反而跑不了。所以没用箭头函数、没用 `??`、没用 `str_contains`，`hash_equals` 有 fallback 实现。

⚠️ **实际验证到 5.6.40**（完整 HTTP 路径，见 SELF-TEST 的 K/L 段）。5.4 和 5.5 是照 5.4 的语法约束写的，但**没能在真机上跑过** —— 那两个镜像在本机镜像源上拉不下来（digest 不匹配）。要在 5.4/5.5 上部署，先自己 `php -l probe.php` 跑一遍。

**为什么 `audit.sh` 一个文件？** 要能 `ssh host 'bash -s' < audit.sh` 直接跑，不需要 scp、不需要装东西、不依赖目标机器上有 python/jq。除了 `bash`，只依赖 coreutils 里最基本的东西，外加可选的 `dpkg`/`rpm`/`docker`。

**为什么默认连 docker 一起查？** 因为现在「PHP 装在哪」这个问题，答案有一半在容器里。反过来也给了 `--no-docker`，跑在容器内部时用得上（不然会去连不存在的 daemon）。

**为什么 `unknown` 不合并进 `affected`？** 因为把「判不了」说成「中了」和说成「没中」一样有害。前者让人白忙、失去信任，后者让人放下戒备。`unknown` 是一个诚实的答案，配一句「该怎么去查清楚」。

---

## 边界

- **只在自己能碰的机器上跑。** 不做任何外部扫描，不碰公网目标。`probe.php` 需要你自己放上去，还需要你自己配令牌。
- **不含利用代码。** 这是防御工具，只读、只报。
- **不写配置。** 两个形态都不会修改 `php.ini`、不会写 drop-in、不会重启服务。修复动作留给人。（对比 NCSC 的 `php2shell-mitigate.sh`，那个会写 drop-in 并重启 Apache —— 它是缓解工具，这个是检测工具。）
- **唯一会写的路径**：`audit.sh` 在 `$TMPDIR` 下建临时目录存中间结果，`trap` 退出时删掉。

## 版本

- v0.1.0 — 首版。两个形态可跑，覆盖链、backport 判定、docker、9 项关键 ini、三档处置代价（`mitigation_impact`）。
- 已知未做：SAPI 运行态的 `litespeed` / `frankenphp` 只在 `/proc` 可读时判得准；非 Linux 的 mod_php 运行态检测缺失；`.htaccess` 是否被 `AllowOverride` 放行未判断；PHP 5.4/5.5 未在真机验证。

## 参考

- PHP 安全公告 · [php.net/archive/2026.php](https://www.php.net/archive/2026.php)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- 补丁 [3584a98](https://github.com/php/php-src/commit/3584a98bda) — 300 files，Zend 引擎
- NCSC `detection_mitigation/cpanel/php2shell-mitigate.sh` — dry-run 默认、可 rollback、只写 drop-in、扫 `/home` 覆盖，本项目的工程写法参考了它
- [JFrog 分析](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/) — 三条臂（upload_progress / fatal_error_backtraces / OPcache）
