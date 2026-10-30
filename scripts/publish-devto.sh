#!/usr/bin/env bash
# publish-devto.sh —— 把一篇 markdown 发到 dev.to
#
#   DEVTO_API_KEY=xxx ./scripts/publish-devto.sh --file post.md
#   ./scripts/publish-devto.sh --file post.md --dry-run
#
# 为什么要有这个脚本：dev.to 是少数从这台机器能通的发布位（HN/Reddit 均 000），
# 但发帖需要账号 API key。脚本先做好、先能验，钥匙一到就能发，不用当场现写。
#
# 安全：key 只从环境变量或 ~/.openclaw/secrets/devto.key 读，**从不回显、不进日志**。
set -uo pipefail

FILE=''
DRY=0
TAGS='php,security,tooling'
PUBLISHED='false'
TITLE=''

usage() {
	cat >&2 <<'USAGE'
用法: publish-devto.sh --file <markdown> [选项]
  --file <path>       要发的 markdown（必填）
  --title <str>       标题（默认取文件里第一个 "# " 行）
  --tags <a,b,c>      标签，最多 4 个（默认 php,security,tooling）
  --publish           直接发布；默认是草稿(false)
  --dry-run           只打印将要发送的 payload，不发请求
USAGE
	exit 64
}

while [ $# -gt 0 ]; do
	case $1 in
		--file)    FILE=${2:?}; shift 2 ;;
		--title)   TITLE=${2:?}; shift 2 ;;
		--tags)    TAGS=${2:?}; shift 2 ;;
		--publish) PUBLISHED='true'; shift ;;
		--dry-run) DRY=1; shift ;;
		-h|--help) usage ;;
		*) echo "未知参数: $1" >&2; usage ;;
	esac
done

[ -n "$FILE" ] || usage
[ -r "$FILE" ] || { echo "读不到文件: $FILE" >&2; exit 66; }

if [ -z "$TITLE" ]; then
	TITLE=$(grep -m1 '^#[[:space:]]\+' "$FILE" 2>/dev/null | sed 's/^#[[:space:]]*//')
fi
[ -n "$TITLE" ] || { echo "没找到标题，用 --title 指定" >&2; exit 65; }

# 标签最多 4 个
TAGS=$(printf '%s' "$TAGS" | awk -F, '{for(i=1;i<=NF && i<=4;i++) printf "%s%s", (i>1?",":""), $i}')

PAYLOAD=$(python3 - "$FILE" "$TITLE" "$TAGS" "$PUBLISHED" <<'PY'
import json, sys
path, title, tags, published = sys.argv[1:5]
body = open(path, encoding='utf-8').read()
# 去掉首行标题，dev.to 用 title 字段单独存
lines = body.split('\n')
if lines and lines[0].lstrip().startswith('#'):
    lines = lines[1:]
    while lines and not lines[0].strip():
        lines.pop(0)
print(json.dumps({
    "article": {
        "title": title,
        "published": published == 'true',
        "body_markdown": '\n'.join(lines),
        "tags": tags,
    }
}, ensure_ascii=False))
PY
) || exit 70

if [ "$DRY" = 1 ]; then
	echo "=== 将发送（不实际请求）==="
	printf '%s' "$PAYLOAD" | python3 -c 'import json,sys; d=json.load(sys.stdin)["article"]; print("title    :",d["title"]); print("published:",d["published"]); print("tags     :",d["tags"]); print("body 字符数:",len(d["body_markdown"])); print("\n--- 正文前 300 字 ---"); print(d["body_markdown"][:300])'
	exit 0
fi

KEY=${DEVTO_API_KEY:-}
[ -n "$KEY" ] || { [ -r "$HOME/.openclaw/secrets/devto.key" ] && KEY=$(tr -d '\r\n' < "$HOME/.openclaw/secrets/devto.key"); }
[ -n "$KEY" ] || { echo "没有 DEVTO_API_KEY（环境变量或 ~/.openclaw/secrets/devto.key）——未发送" >&2; exit 78; }

CODE=$(printf '%s' "$PAYLOAD" | curl -s -o /tmp/devto-resp.json -w '%{http_code}' \
	-m 60 -X POST https://dev.to/api/articles \
	-H "api-key: $KEY" \
	-H 'Content-Type: application/json' \
	--data-binary @-)

echo "HTTP $CODE"
case $CODE in
	201)
		python3 -c 'import json; d=json.load(open("/tmp/devto-resp.json")); print("已发布:", d.get("url") or d.get("canonical_url") or "(无 url 字段)")'
		;;
	401|403)
		echo "认证失败——key 无效或无发布权限。未写入任何内容。" >&2
		exit 1
		;;
	*)
		echo "失败，响应：" >&2
		head -c 400 /tmp/devto-resp.json >&2
		exit 1
		;;
esac
