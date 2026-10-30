# BACKLOG — 事实级候选改动

给 `scripts/patrol.sh` 读的。**每一条都必须带文件路径和复核命令**——巡检报「你断更了」的时候，从这里挑三条一起报出去。
只有「事实级」的进这张表：一条改动落下去，仓库里至少有一句话比昨天更真，或多覆盖一个真实对象。

格式是硬约定（脚本按 `### ID · 标题` 切块，按 `- key: value` 读字段）：

```
### ID · 标题
- files: `path:line`, `path:line`
- value: 高 | 中 | 低
- size: S | M | L
- status: open | claimed | done
- why: 一句话说清「哪一处事实会变真」
- verify: 一条能跑的复核命令
```

`status` 只有 `open` 会被巡检挑中；`claimed` 是有人认领了还没落；`done` 留着当账。

---

## 候选

### SCAN-HANG · 默认扫描路径不退出（没有真实 webroot 时挂死）
- files: `audit.sh`（`scan_lfi_sinks` / `collect_webroots` 调用链）
- value: 高
- size: M
- status: open
- why: `./audit.sh --no-docker --root /tmp/nonexistent` 会打印完整报告，然后**进程不退出**——`timeout 12` 必得 124。加 `--no-scan` 秒退（exit 2）。**自检第 9 节正是跑这一条，所以 `lab/selftest.sh` 每次都停在那里，31 条只能跑到 9 条**，README/SELF-TEST 里的「31 PASS / 0 FAIL」因此无法复验。扫描器挂死比报空更糟：调用方拿不到退出码，分不清「跑完了没问题」和「卡住了」。
- verify: `timeout 12 ./audit.sh --no-docker --root /tmp/nonexistent; echo $?` 现在得 124，改后应得 2；再跑 `cd lab && ./selftest.sh` 应能跑满 31 条并打出最终统计。
- note: 已排除的假设——① 不是今天 `eeb7e2d` 引入：`git show dad4460:audit.sh` 与 `28e5e58:audit.sh` 两版同样 124；② 不是假 php：换真 php 一样卡；③ 不是 EXIT trap 的 `rm -rf`：手动删同目录 0.005s；④ 不是 cwd：repo 根 / `/tmp` / `lab` 三处一样卡。

### LFI-CHAIN-MULTIHOP · 追一层变量赋值链（v0.2 第一刀）
- files: `audit.sh:962`
- value: 高
- size: M
- status: open
- why: 现在只认「sink 的变量在同一文件里被直接赋成 $_GET/$_POST/…」这一跳；`$a=$_GET['f']; $b=$a; include $b;` 这种一层中转就漏。漏的是真实站点里最常见的那种写法。
- verify: 在 `lab/webroot` 造一个两跳样本，`scan_lfi_sinks` 现在报 0 条，改后报 1 条（indirect）；再把样本挪进 SELF-TEST 当断言。

### LFI-HEAD3 · `head -3` 把第 4 个 sink 截掉了
- files: `audit.sh:948`, `audit.sh:955`
- value: 高
- size: S
- status: open
- why: 每个文件每种形态只取前 3 行命中；超过 3 处的文件后面全部看不见。这是**假阴性**，且不报「我截断了」。
- verify: 造一个 5 个 `include $_GET[...]` 的文件，现在输出 3 行；改后输出 5 行，或在截断时于 JSON 里标 `truncated: true`。

### CHANGELOG-HEAD80 · changelog 只读前 80 行
- files: `audit.sh:257`, `audit.sh:263`
- value: 高
- size: S
- status: open
- why: `gzip -dc … | head -80` 和 `rpm -q --changelog | head -80`。老发行版的 changelog 动辄上千行，CVE 条目常常在 80 行之外 → `package_changelog` 空 → 「changelog 未命中」。同样是假阴性，而且它出现在「补丁修没修」这个最要紧的判断上。
- verify: 造一个 CVE 条目在第 200 行的 changelog 假文件，现在 `changelog_hit` 返回 1（未命中），改后返回 0 并打印文件路径。

### DOC-ANCHORS · `docs/EVIDENCE-SCHEMA.md` 的 10 处行号没有 grep 锚点
- files: `docs/EVIDENCE-SCHEMA.md:290`, `MAINTAINING.md:80`
- value: 中
- size: S
- status: open
- why: MAINTAINING §4.1 要求「绝对行号 + grep 锚点」两件套；EVIDENCE-SCHEMA 里 10 处 `audit.sh:LINE` 只有行号。行号一漂，文档就指向别的代码，而读者不会发现。
- verify: `grep -cE 'audit\.sh:[0-9]+' docs/EVIDENCE-SCHEMA.md` → 10；逐条 `sed -n 'Np'` 打开，把命中的函数名/字面量补在行号后面，再 grep 一次锚点，10/10 能定位。

### GHMETA-TOKEN · `gh-meta.sh` 没法用 token，60 次/小时一到就瞎
- files: `scripts/gh-meta.sh:27`
- value: 中
- size: S
- status: open
- why: 只发匿名请求。加一条 `GITHUB_TOKEN` 存在就带上 `Authorization` 的分支，**状态码先验的规矩不变**（403 仍然只报「读取失败」）。事实变化：同一个仓库，限额从 60/h 变成 5000/h。
- verify: `GITHUB_TOKEN=… ./scripts/gh-meta.sh` 输出三字段且都标 `(HTTP 200)`；再把 token 换成假的，仍必须打印 `读取失败（HTTP 401）`、不输出任何字段。

### SELFTEST-README-COUNT · 断言 README 声明的 PASS 数 == 实际 `[PASS]` 行数
- files: `lab/selftest.sh`, `README.md:502`
- value: 高
- size: S
- status: claimed
- why: 2026-10-25 手动数错过一次：`grep -cE '\bPASS\b'` 得 35（含汇总行和一句「测出假 PASS」），`grep -cE '\[PASS\]'` 得 31。手动会错的数，就让机器每天数。
- verify: 故意把 README 里的 31 改成 35，`bash lab/selftest.sh` 必须 FAIL 并指出声明值与实际值。
- note: 2026-10-25 由对端认领，本表只记账，不重复挑。

### NOOP-HONESTY · 空档声明本身也要有据
- files: `docs/PATROL.md`, `scripts/patrol.sh`
- value: 低
- size: S
- status: open
- why: 「今天没东西可说」是合法答案，但空档声明的理由要落盘（`.patrol/ack-<date>.txt`），连续多天声明空档要在巡检里显示出来。防的不是懒惰，是「声明空档」变成新的填格动作。
- verify: 连续三份 ack，巡检必须打印「连续 3 天声明空档」，并且仍然给三条候选——不给方向的预警不算预警。
