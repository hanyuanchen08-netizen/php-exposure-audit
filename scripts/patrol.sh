#!/usr/bin/env bash
# patrol.sh — 每日巡检 + 断更预警
#
# 存在的理由：没人催的仓库不会因为懒而烂，会因为没有方向的提醒而烂。
# 所以这个脚本被规定只允许说三件事：
#   1. 昨天到今天，仓库里有没有一句话变得更真（事实级提交）
#   2. README 里写死的数字，现在还对得上吗（活的自检）
#   3. 如果今天空着，那今天可以做什么（三条候选，带文件路径）
#
# 它不做的事（同样重要）：
#   - 不 commit、不改任何文件（除了 .patrol/ 下的空档声明）
#   - 不因为断更就报「复利归零」。断一天是那天没东西可说，不是欠账
#   - 不把「commits/天」当指标。凑数的 commit 会污染历史，空一天不会
#
# 用法:
#   ./scripts/patrol.sh                 # 全量报告（人看）
#   ./scripts/patrol.sh --brief         # 一行结论（cron 用）
#   ./scripts/patrol.sh candidates      # 只出今天的三条候选
#   ./scripts/patrol.sh ack "理由"      # 声明今天空档（要写理由，不写不让过）
#   ./scripts/patrol.sh claims          # 只核 README 里的数字
#
# 退出码: 0 = 正常 / 1 = 用法或环境错 / 2 = 需要人看一眼（断更≥3天、数字漂了）

set -uo pipefail

REPO="${PATROL_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO" || { echo "进不去仓库: $REPO" >&2; exit 1; }

NOW="${PATROL_NOW:-$(date +%F)}"
STATE_DIR="$REPO/.patrol"
ACK="$STATE_DIR/ack-$NOW.txt"

# 断更阈值（天）。1 天不算事，2 天留意，3 天起叫人。
WATCH_DAYS=2
ALERT_DAYS=3
CANDIDATES=3

epoch_of() { # $1=YYYY-MM-DD
	if date -j -f '%Y-%m-%d' "$1" +%s >/dev/null 2>&1; then
		date -j -f '%Y-%m-%d' "$1" +%s
	else
		date -d "$1" +%s
	fi
}

day_of_year() { # $1=YYYY-MM-DD
	if date -j -f '%Y-%m-%d' "$1" +%j >/dev/null 2>&1; then
		date -j -f '%Y-%m-%d' "$1" +%j | sed 's/^0*//'
	else
		date -d "$1" +%j | sed 's/^0*//'
	fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- 事实级 ---
# 事实级 = commit message 里有一行 `Fact: <哪一处事实变了>`（或 `事实：`）。
# 答不出这一行的提交，不算日常更新——可能是格式、措辞、排版，也可能是凑数。

is_fact_level() { # $1=sha
	git log -1 --format=%B "$1" 2>/dev/null \
		| grep -qiE '^(fact|事实)[[:space:]]*[:：][[:space:]]*[^[:space:]]'
}

fmt_only() { # $1=sha  忽略空白后 diff 为空 => 纯格式
	local d
	d=$(git show --format= --ignore-all-space --ignore-blank-lines --unified=0 "$1" 2>/dev/null \
		| grep -E '^[+-][^+-]' | head -1)
	[ -z "$d" ]
}

last_fact_commit() { # -> "sha<TAB>date<TAB>subject"
	git log --format='%H%x09%ad%x09%s' --date=short 2>/dev/null | while IFS=$'\t' read -r sha ad subj; do
		if is_fact_level "$sha"; then printf '%s\t%s\t%s\n' "$sha" "$ad" "$subj"; return; fi
	done | head -1
}

# ---------------------------------------------------------------- 数字核 ---
# 一条数字能写进对外文案，当且仅当给出那条命令别人只能得到一个结果（MAINTAINING §7）。
# 这里只核最容易被手抄错的那条：README 声明的 PASS 数。

claims() { # -> 0 ok / 2 mismatch
	local actual fail declared rc=0 n
	actual=$(grep -cE '\[PASS\]' SELF-TEST.md 2>/dev/null | tr -d '\n')
	fail=$(grep -cE '\[FAIL\]' SELF-TEST.md 2>/dev/null | tr -d '\n')
	actual=${actual:-0}; fail=${fail:-0}
	declared=$(grep -oE '[0-9]+[[:space:]]+PASS' README.md 2>/dev/null | grep -oE '^[0-9]+' | sort -u)

	printf 'SELF-TEST 实测: [PASS]=%s  [FAIL]=%s\n' "$actual" "$fail"
	if [ "$fail" != "0" ]; then
		printf '❌ SELF-TEST 里有 %s 条 FAIL —— 先修 FAIL，数字没意义\n' "$fail"
		rc=2
	fi
	if [ -z "$declared" ]; then
		printf '⚠️  README 里没找到「N PASS」声明（口径变了？）\n'
		return 1
	fi
	for n in $declared; do
		if [ "$n" = "$actual" ]; then
			printf '✅ README 声明 %s PASS == 实测 %s\n' "$n" "$actual"
		else
			printf '❌ README 声明 %s PASS，实测 %s —— 数字漂了\n' "$n" "$actual"
			printf '   复现: grep -cE "\\[PASS\\]" SELF-TEST.md\n'
			printf '   注意: 用 \\bPASS\\b 数会多出汇总行，别拿那个数改 README\n'
			rc=2
		fi
	done
	return $rc
}

# ---------------------------------------------------------------- 候选 ---
# BACKLOG.md 格式见该文件头。按日期轮转，保证同一天给的是同一组三条，
# 但不会一个月都是同三条。

pick_candidates() { # $1=n
	local n=${1:-$CANDIDATES} i idx total day
	# 注意: 标量名不能和数组同名（bash 里 read 进数组变量会写到 [0]）
	local -a c_id c_title c_files c_why c_verify
	while IFS=$'\t' read -r id title files why verify; do
		c_id+=("$id"); c_title+=("$title"); c_files+=("$files"); c_why+=("$why"); c_verify+=("$verify")
	done < <(awk '
		function flush() { if (id != "" && status == "open") printf "%s\t%s\t%s\t%s\t%s\n", id, title, files, why, verify }
		/^```/ { fence = !fence; next }
		fence { next }
		/^### / {
			flush()
			line = $0; sub(/^### /, "", line)
			if (line ~ /^[A-Z][A-Z0-9-]* · /) {
				id = line; sub(/ · .*/, "", id)
				title = line; sub(/^[^·]*· /, "", title)
				files = ""; why = ""; verify = ""; status = "open"
			} else { id = "" }
			next
		}
		/^- files:/    { v = $0; sub(/^- files:[[:space:]]*/, "", v); gsub(/`/, "", v); files = v }
		/^- status:/   { v = $0; sub(/^- status:[[:space:]]*/, "", v); status = v }
		/^- why:/      { v = $0; sub(/^- why:[[:space:]]*/, "", v); why = v }
		/^- verify:/   { v = $0; sub(/^- verify:[[:space:]]*/, "", v); verify = v }
		END { flush() }
	' BACKLOG.md)

	total=${#c_id[@]}
	[ "$total" -gt 0 ] || { printf '（BACKLOG.md 里没有 open 条目——那本身就是今天该补的事）\n'; return 0; }

	day=$(day_of_year "$NOW")
	[ "$n" -gt "$total" ] && n=$total
	for ((i = 0; i < n; i++)); do
		idx=$(( (day + i) % total ))
		[ "$idx" -lt 0 ] && idx=$(( idx + total ))
		printf '%d. %s — %s\n   files: %s\n   %s\n   复核: %s\n' \
			"$((i + 1))" "${c_id[$idx]}" "${c_title[$idx]}" "${c_files[$idx]}" "${c_why[$idx]}" "${c_verify[$idx]}"
	done
}

print_candidates() {
	printf '\n今天可以做的（%d 条，带路径）：\n' "$CANDIDATES"
	pick_candidates "$CANDIDATES"
	printf '\n挑一条做，或告诉我今天真没有。**「没有」也是答案**，但要落盘：./scripts/patrol.sh ack "理由"\n'
}

# ---------------------------------------------------------------- 主流程 ---
cmd=${1:-report}

case $cmd in
	candidates)
		pick_candidates "${2:-$CANDIDATES}"
		exit 0
		;;

	ack)
		reason=${2:-}
		if [ -z "$reason" ]; then
			echo '用法: ./scripts/patrol.sh ack "今天为什么没有事实级改动"' >&2
			echo '没理由的空档声明不算空档，只算把格子填上。' >&2
			exit 1
		fi
		mkdir -p "$STATE_DIR"
		printf '%s\t%s\t%s\n' "$NOW" "$(git log -1 --format=%h 2>/dev/null)" "$reason" > "$ACK"
		printf '已声明空档 %s: %s\n（这份声明不进 git，不制造 commit）\n' "$NOW" "$reason"
		exit 0
		;;

	claims)
		claims
		exit $?
		;;
esac

# 下面两种是报告模式
brief=0
[ "$cmd" = '--brief' ] && brief=1

head_sha=$(git log -1 --format='%h' 2>/dev/null)
head_subj=$(git log -1 --format='%s' 2>/dev/null)
[ -n "$head_sha" ] || { echo "不是 git 仓库: $REPO" >&2; exit 1; }

read -r last_sha last_date last_subj <<<"$(last_fact_commit || true)"
fact_basis=''
days=999
if [ -n "${last_date:-}" ]; then
	fact_basis=$last_date
	days=$(( ( $(epoch_of "$NOW") - $(epoch_of "$last_date") ) / 86400 ))
else
	# Fact: 规则自 2026-10-25 起。历史提交不追溯，按 HEAD 提交日计，并标明口径。
	fact_basis=$(git log -1 --format=%ad --date=short 2>/dev/null)
	[ -n "$fact_basis" ] && days=$(( ( $(epoch_of "$NOW") - $(epoch_of "$fact_basis") ) / 86400 ))
fi

recent_total=$(git log --since="$NOW -14 days" --format='%h' 2>/dev/null | wc -l | tr -d ' ')
recent_fact=$(git log --since="$NOW -14 days" --format='%h' 2>/dev/null | while read -r s; do
	[ -n "$s" ] && is_fact_level "$s" && echo "$s"
done | wc -l | tr -d ' ')
recent_fmt=$(git log --since="$NOW -14 days" --format='%h' 2>/dev/null | while read -r s; do
	[ -n "$s" ] && ! is_fact_level "$s" && fmt_only "$s" && echo "$s"
done | wc -l | tr -d ' ')

ack_reason=''
[ -f "$ACK" ] && ack_reason=$(cut -f3 "$ACK")

# 空档声明累计份数（只数落盘的，不猜）
ack_streak=$(ls "$STATE_DIR"/ack-*.txt 2>/dev/null | wc -l | tr -d ' ')

state=ok
if [ "$days" -ge "$ALERT_DAYS" ]; then state=alert
elif [ "$days" -ge "$WATCH_DAYS" ]; then state=watch
fi

today_fact=no
[ -n "${last_date:-}" ] && [ "$last_date" = "$NOW" ] && today_fact=yes

# ---- brief ----
if [ "$brief" = 1 ]; then
	printf 'patrol %s %s days=%s today_fact=%s fact14=%s/%s' \
		"$NOW" "$state" "$days" "$today_fact" "$recent_fact" "$recent_total"
	[ -n "$ack_reason" ] && printf ' ack=yes'
	printf '\n'
	exit $([ "$state" = alert ] && echo 2 || echo 0)
fi

# ---- 全量 ----
printf '巡检 %s · %s@%s\n' "$NOW" "$(basename "$REPO")" "$head_sha"
printf '  HEAD: %s\n\n' "${head_subj:-（空仓）}"

printf '仓库事实\n'
if [ -n "${last_date:-}" ]; then
	printf '  最近事实级提交: %s（%s 天前）%s\n' "$last_date" "$days" "$last_subj"
else
	printf '  最近事实级提交: 无标注 —— Fact: 规则 2026-10-25 起，历史不追溯\n'
	printf '  按 HEAD 提交日计: %s（%s 天前）—— 这是最大天数，不是欠账\n' "${fact_basis:-未知}" "$days"
fi
printf '  今日事实级提交: %s\n' "$([ "$today_fact" = yes ] && echo '有' || echo '无')"
printf '  近 14 天: 事实级 %s / 总 %s' "$recent_fact" "$recent_total"
[ "$recent_fmt" -gt 0 ] && printf '（其中 %s 条是纯空白/格式改动，不算日常更新）' "$recent_fmt"
printf '\n\n'

printf '数字自检\n'
crc=0; claims || crc=$?

printf '\n判定: '
case $state in
	ok)    [ "$today_fact" = yes ] && echo '✅ 今天有事实级提交。' || echo '🟢 今天还空着 —— 正常，不欠账。';;
	watch) printf '🟡 已经 %s 天没有事实级提交。留意一下，不用紧张。\n' "$days";;
	alert) printf '🟠 已经 %s 天没有事实级提交。\n      断更本身不是罪，无声断更才是：下面三条是今天的出口。\n' "$days";;
esac

if [ -n "$ack_reason" ]; then
	printf '  今天已声明空档: %s\n' "$ack_reason"
	if [ "$ack_streak" -ge 3 ]; then
		printf '  ⚠️  .patrol 里累计 %s 份空档声明 —— 不犯规，但值得看一眼 backlog 里有没有 S 号票\n' "$ack_streak"
	fi
fi

if [ "$today_fact" = no ]; then
	print_candidates
fi

if [ "$crc" = 2 ]; then
	printf '\n⚠️  数字自检没过 —— 这一条比断更优先。先改数字，再谈今天做什么。\n'
fi

[ "$state" = alert ] && exit 2
[ "$crc" = 2 ] && exit 2
exit 0
