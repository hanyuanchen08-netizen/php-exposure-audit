#!/usr/bin/env bash
# gh-meta.sh — 取仓库元数据（license / description / topics）
#
# 存在的理由：2026-10-23 有一次把 GitHub API 的 403 限流响应读成了
# 「仓库 license 掉了」。解析器遇到错误对象时静默返回空字段，
# 于是「读不到」变成了「变了」。
#
# 所以这个脚本的顺序是硬性的：
#   1. 先看 HTTP 状态码，非 200 就报错退出，一个字段都不输出
#   2. 再校验响应体里字段齐不齐，缺了就拒绝解读
#   3. 全部通过才打印，且每个字段后面标 (HTTP 200)
#
# 用法:
#   ./scripts/gh-meta.sh                     # 默认本仓
#   ./scripts/gh-meta.sh owner/repo          # 指定仓库
#
# 注意: 未认证 API 限额 60 次/小时。一次调用就能拿全三个字段，
#       不要拆成三次查。核代码内容请用 git clone（走 SSH，零配额）。

set -euo pipefail

REPO="${1:-hanyuanchen08-netizen/php-exposure-audit}"
URL="https://api.github.com/repos/${REPO}"

BODY="$(mktemp)"
trap 'rm -f "$BODY"' EXIT

CODE="$(curl -sS -o "$BODY" -w '%{http_code}' --max-time 15 "$URL" 2>/dev/null || echo 000)"

if [ "$CODE" != "200" ]; then
    printf '读取失败（HTTP %s）—— 不报对象状态\n' "$CODE"
    python3 - "$BODY" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
msg = d.get("message")
if msg:
    print("  API 说明:", msg)
PY
    case "$CODE" in
        403|429) echo "  → 多半是未认证限额用尽（60/h）。看 X-RateLimit-Reset 或 /rate_limit。" ;;
        000)     echo "  → 连不上。检查域名是否被拦、DNS、代理。" ;;
        404)     echo "  → 仓库不存在，或私有且无权限。" ;;
    esac
    exit 1
fi

python3 - "$BODY" <<'PY'
import json, sys

d = json.load(open(sys.argv[1]))

required = ("license", "description", "topics")
missing = [k for k in required if k not in d]
if missing:
    sys.exit("响应体缺字段，拒绝解读: " + ", ".join(missing))

spdx = (d.get("license") or {}).get("spdx_id")
print(f"license     : {spdx!s:<12} (HTTP 200)")
print(f"description : {d.get('description')!r} (HTTP 200)")
print(f"topics      : {d.get('topics')} (HTTP 200)")
print(f"pushed_at   : {d.get('pushed_at')} (HTTP 200)")
PY
