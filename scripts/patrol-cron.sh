#!/usr/bin/env bash
# cron 入口（19:30 每日维护巡检）
#
# 只有两种情况说话：
#   1. 今天没有 Fact: 级提交
#   2. 断更 ≥3 天、或 README 声明数字与实测不符（patrol.sh 退出码非 0）
# 其余情况**无输出** → cron 判 empty → 不投递。
#
# 判据说明（2026-10-25 白也提醒后确认）：
#   patrol.sh --notify 的退出码只有 0 / 2，断更 1–2 天时退出码仍是 0。
#   所以**不能只看退出码**，要看 --brief 输出里的 today_fact= 字段。
#
# 「昨日：」那行 patrol.sh 自己拿不到（要联网取 ★/fork/issue），按它的设计
# 由外部注入 PATROL_STATS。这里只注入能从 git 算出来、且不需要联网的那部分：
# 昨日 Fact 条数。星数拿不到就不写——**不编一个 0 上去**。

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

s=$(bash scripts/patrol.sh --brief 2>/dev/null)
rc=$?

if [ "$rc" -eq 0 ] && printf '%s' "$s" | grep -q 'today_fact=yes'; then
	exit 0    # 今天有提交，且没有断更/数字漂 → 闭嘴
fi

# 昨日 Fact 条数走 patrol.sh 自己的 --yesterday-facts ——
# 「事实级」在全仓只能有一个定义（is_fact_level 会排除「带 Fact: 但 diff 为空」的纯格式改动）。
# 这里原来用 python 另算一套，两套口径早晚对不上。
yf=$(bash scripts/patrol.sh --yesterday-facts 2>/dev/null || echo 0)

PATROL_STATS="+${yf} 条 Fact" bash scripts/patrol.sh --notify
