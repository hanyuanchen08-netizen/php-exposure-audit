#!/usr/bin/env bash
# 靶场自检 —— 复跑 SELF-TEST.md 里的每一条。
#
#   cd lab && ./selftest.sh            # 全部
#   cd lab && ./selftest.sh 2>&1 | tee /tmp/out.txt
#
# 前置：两个容器已经起来（docker-compose up -d），PEA_TOKEN 已知或从 .pea-token 读。
set -uo pipefail
cd "$(dirname "$0")"

TOKEN=${PEA_TOKEN:-$(cat .pea-token 2>/dev/null)}
if [ -z "${TOKEN:-}" ]; then
	echo "PEA_TOKEN 未设置，且 .pea-token 不存在" >&2
	exit 2
fi

VULN=18091
FIXED=18092
PASS=0
FAIL=0

hr() { printf '\n%s\n' "----------------------------------------------------------------"; }
sec() { hr; printf '%s\n' "$*"; hr; }

# $1 描述, $2 期望, $3 实际
check() {
	if [ "$2" = "$3" ]; then
		printf '  [PASS] %-46s %s\n' "$1" "$3"
		PASS=$((PASS + 1))
	else
		printf '  [FAIL] %-46s 期望 %s，实际 %s\n' "$1" "$2" "$3"
		FAIL=$((FAIL + 1))
	fi
}

jsonq() {
	# $1 url, $2 python expr against d
	python3 -c '
import json,sys
d=json.load(sys.stdin)
print('"$2"')'
}

sec "0. 环境"
echo '$ docker ps --format "{{.Names}}\t{{.Status}}\t{{.Ports}}"'
docker ps --format '{{.Names}}	{{.Status}}	{{.Ports}}' | grep pea || { echo "容器没起来"; exit 2; }

sec "1. 靶场在线"
echo "\$ curl -s http://127.0.0.1:$VULN/index.php"
curl -s -m 10 "http://127.0.0.1:$VULN/index.php"
echo "\$ curl -s http://127.0.0.1:$FIXED/index.php"
curl -s -m 10 "http://127.0.0.1:$FIXED/index.php"

sec "2. probe.php 鉴权：无 token 必须是 404"
echo "\$ curl -si http://127.0.0.1:$VULN/probe.php | head -1"
curl -s -m 10 -D - -o /dev/null "http://127.0.0.1:$VULN/probe.php" | head -1
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$VULN/probe.php")
check "无 token → 404" 404 "$code"

echo "\$ curl -s -o /dev/null -w '%{http_code}' -H 'X-Audit-Token: wrong' .../probe.php"
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H 'X-Audit-Token: wrong' "http://127.0.0.1:$VULN/probe.php")
check "错 token → 404" 404 "$code"

echo "\$ curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer '\$TOKEN .../probe.php"
code=$(curl -s -m 20 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$VULN/probe.php")
check "Bearer token → 200" 200 "$code"

echo "\$ curl -s .../probe.php  （404 body，应和 Apache 默认 404 无区别）"
curl -s -m 10 "http://127.0.0.1:$VULN/probe.php"

sec "3. probe.php 判 affected —— PHP 8.5.11 + mod_php"
echo "\$ curl -s -H 'X-Audit-Token: ...' 'http://127.0.0.1:$VULN/probe.php?format=json' | python3 -m json.tool"
curl -s -m 25 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$VULN/probe.php?format=json" | python3 -m json.tool
v=$(curl -s -m 25 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$VULN/probe.php?format=json" | jsonq x 'd["verdict"]')
check "8.5.11 probe verdict" affected "$v"
m=$(curl -s -m 25 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$VULN/probe.php?format=json" | jsonq x 'd["runtime"]["sapi_flags"]["mod_php"]')
check "8.5.11 检出 mod_php" True "$m"
u=$(curl -s -m 25 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$VULN/probe.php?format=json" | jsonq x 'd["ini"]["session.upload_progress.enabled"]["value"]')
check "报出 upload_progress 当前值" 1 "$u"

sec "4. probe.php 判 patched —— PHP 8.5.12 + mod_php"
echo "\$ curl -s -H 'X-Audit-Token: ...' 'http://127.0.0.1:$FIXED/probe.php?format=json'"
echo "  （全量 JSON 见第 3 节，字段结构一致；这里只摘判定相关字段，都是原样输出）"
curl -s -m 25 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$FIXED/probe.php?format=json" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("verdict      :", d["verdict"], "/", d["verdict_label_zh"], "| confidence", d["confidence"], "| exit", d["exit_code"])
print("reason       :", d["verdict_reason"])
print("php_version  :", d["runtime"]["php_version"])
print("sapi         :", d["runtime"]["sapi"], "mod_php=", d["runtime"]["sapi_flags"]["mod_php"])
print("marker_state :", d["backport"]["marker_state"])
print("evidence     :", d["backport"]["evidence"])
print("upload_prog  :", d["ini"]["session.upload_progress.enabled"]["value"],
      "(", d["ini"]["session.upload_progress.enabled"]["state"], ")")
print("backtraces   :", d["ini"]["fatal_error_backtraces"]["value"],
      "(", d["ini"]["fatal_error_backtraces"]["state"], ")")
print("chain        :", len(d["coverage_chain"]["files"]), "files, weakening", d["coverage_chain"]["weakening_count"])
print("action       :", d["action"])
'
v=$(curl -s -m 25 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$FIXED/probe.php?format=json" | jsonq x 'd["verdict"]')
check "8.5.12 probe verdict" patched "$v"

sec "5. audit.sh 在受影响容器内（8.5.11 / mod_php）"
echo '$ docker cp audit.sh pea-lab-vuln:/tmp/audit.sh'
docker cp ../audit.sh pea-lab-vuln:/tmp/audit.sh
echo '$ docker exec pea-lab-vuln bash /tmp/audit.sh --no-docker'
docker exec pea-lab-vuln bash /tmp/audit.sh --no-docker
rc=$(docker exec pea-lab-vuln bash /tmp/audit.sh --no-docker >/dev/null 2>&1; echo $?)
echo "exit code: $rc"
check "audit.sh 8.5.11 退出码" 1 "$rc"

sec "6. audit.sh 在已修容器内（8.5.12 / mod_php）"
echo '$ docker cp audit.sh pea-lab-fixed:/tmp/audit.sh'
docker cp ../audit.sh pea-lab-fixed:/tmp/audit.sh
echo '$ docker exec pea-lab-fixed bash /tmp/audit.sh --no-docker'
docker exec pea-lab-fixed bash /tmp/audit.sh --no-docker
rc=$(docker exec pea-lab-fixed bash /tmp/audit.sh --no-docker >/dev/null 2>&1; echo $?)
echo "exit code: $rc"
check "audit.sh 8.5.12 退出码" 0 "$rc"

sec "7. audit.sh --json（受影响容器，完整 schema）"
echo '$ docker exec pea-lab-vuln bash /tmp/audit.sh --no-docker --json | python3 -m json.tool'
docker exec pea-lab-vuln bash /tmp/audit.sh --no-docker --json 2>/dev/null | python3 -m json.tool

sec "8. 版本判定矩阵（函数级单测）"
echo "\$ bash -c 'source ../audit.sh; classify_version <ver>'"
bash -c 'source ../audit.sh; for v in 5.3.29 5.4.0 7.4.33 8.1.30 8.2.34 8.2.35 8.3.36 8.4.26 8.4.27 8.5.11 8.5.12 8.6.0; do printf "%-9s %s\n" "$v" "$(classify_version "$v" | tr "\t" " ")"; done'

sec "9. 判不了（unknown）+ 退出码 2"
echo '# 假 php 二进制报告 8.6.0 —— 在公告区间之上，工具必须拒绝猜'
mkdir -p /tmp/fakephp/bin
cat > /tmp/fakephp/bin/php <<'SH'
#!/bin/sh
case "$*" in
  *PHP_VERSION*) printf '8.6.0' ;;
  *PHP_SAPI*) printf 'cli' ;;
  *PHP_OS*) printf 'Linux' ;;
  *zend_version*) printf '4.6.0' ;;
  *PHP_INT_SIZE*) printf '64' ;;
  *--ini*) printf 'Loaded Configuration File:         (none)\nScan for additional .ini files in: (none)\n' ;;
  *'-i'*) printf 'Build Date => Oct 21 2026 00:00:00\n' ;;
  *'-v'*) printf 'PHP 8.6.0 (cli)\n' ;;
  *) printf '' ;;
esac
SH
chmod +x /tmp/fakephp/bin/php
echo '$ PATH=/tmp/fakephp/bin:$PATH ../audit.sh --no-docker --root /tmp/nonexistent'
PATH="/tmp/fakephp/bin:$PATH" ../audit.sh --no-docker --root /tmp/nonexistent
rc=$(PATH="/tmp/fakephp/bin:$PATH" ../audit.sh --no-docker --root /tmp/nonexistent >/dev/null 2>&1; echo $?)
echo "exit code: $rc"
check "unknown 退出码" 2 "$rc"

sec "10. ssh 管道模式（bash -s，不需要拷贝文件）"
echo '$ cat ../audit.sh | docker exec -i pea-lab-vuln bash -s -- --no-docker | head -9'
cat ../audit.sh | docker exec -i pea-lab-vuln bash -s -- --no-docker 2>&1 | head -9
rc=$(cat ../audit.sh | docker exec -i pea-lab-vuln bash -s -- --no-docker >/dev/null 2>&1; echo $?)
echo "exit code: $rc"
check "bash -s 管道退出码" 1 "$rc"

sec "11. .audit-token 文件模式（不设环境变量，真实 HTTP）"
# 前两节用的容器里有 PHP_EXPOSURE_AUDIT_TOKEN 环境变量，永远走不到文件分支。
# 这里另起一个没有环境变量的容器，webroot 用临时可写副本。
# 必须用 mktemp -d：固定路径 + 上一轮残留（尤其上一轮踩出来的 .audit-token）
# 会让「本来没有 token」这条前提悄无声息地不成立，测出一个假的 PASS。
FM_WEB=$(mktemp -d "${TMPDIR:-/tmp}/pea-filemode.XXXXXX") || exit 3
cp -R ./webroot/. "$FM_WEB"/
docker rm -f pea-filemode >/dev/null 2>&1
echo '$ docker run -d --name pea-filemode -p 18093:80 -v <tmpdir>:/var/www/html ... （不传 token 环境变量）'
docker run -d --name pea-filemode -p 18093:80 \
  -v "$FM_WEB":/var/www/html \
  -v "$(cd .. && pwd)/probe.php":/opt/probe.php:ro \
  docker.m.daocloud.io/library/php:8.5.11-apache \
  bash -c 'cp /opt/probe.php /var/www/html/probe.php && chmod 644 /var/www/html/probe.php && apache2-foreground' >/dev/null
sleep 6

echo '$ docker exec pea-filemode env | grep PHP_EXPOSURE_AUDIT_TOKEN   # 应为空'
docker exec pea-filemode sh -c 'env | grep PHP_EXPOSURE_AUDIT_TOKEN || echo "(none)"'

echo '$ docker exec pea-filemode ls /var/www/html/.audit-token   # 确认不存在'
if docker exec pea-filemode test -e /var/www/html/.audit-token; then
	printf '  [FAIL] %-46s 文件意外存在，前提不成立\n' ".audit-token 不存在"
	FAIL=$((FAIL + 1))
else
	printf '  [PASS] %-46s 不存在\n' ".audit-token 不存在"
	PASS=$((PASS + 1))
fi

echo '$ curl -s -o /dev/null -w "%{http_code}" -H "X-Audit-Token: $TOKEN" .../probe.php   # 还没写 .audit-token'
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H "X-Audit-Token: $TOKEN" http://127.0.0.1:18093/probe.php)
check "无环境变量 + 无 .audit-token → 404" 404 "$code"

echo "\$ docker exec pea-filemode sh -c 'printf %s \$TOKEN > /var/www/html/.audit-token && chmod 644 ...'"
docker exec pea-filemode sh -c "printf '%s' '$TOKEN' > /var/www/html/.audit-token && chmod 644 /var/www/html/.audit-token"
echo '$ curl -s -H "X-Audit-Token: $TOKEN" .../probe.php   # 只靠文件里的 token'
code=$(curl -s -m 20 -o /tmp/pea-fm.json -w '%{http_code}' -H "X-Audit-Token: $TOKEN" http://127.0.0.1:18093/probe.php)
check "文件模式 → 200" 200 "$code"
v=$(python3 -c 'import json;print(json.load(open("/tmp/pea-fm.json"))["verdict"])' 2>/dev/null)
check "文件模式 verdict" affected "$v"

echo '$ curl -s -o /dev/null -w "%{http_code}" -H "X-Audit-Token: wrong" .../probe.php'
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H 'X-Audit-Token: wrong' http://127.0.0.1:18093/probe.php)
check "文件模式 + 错 token → 404" 404 "$code"

echo '# 收尾'
docker rm -f pea-filemode >/dev/null 2>&1
rm -rf "$FM_WEB"
echo '  pea-filemode 已删除，临时 webroot 已清理'

sec "12. mitigation_impact — 三档处置代价（B 档只读扫表）"
echo '# 靶场里预置了 shop/admin/logo.php、shop/product-edit.php、blog/profile.php、blog/wp-admin-async.php'
echo '$ docker exec pea-lab-vuln bash /tmp/audit.sh --no-docker 2>&1 | sed -n "/处置选项/,/只关/p"'
docker exec pea-lab-vuln bash /tmp/audit.sh --no-docker 2>&1 | sed -n '/处置选项/,/只关/p' | head -24

echo
echo '$ curl .../probe.php?format=json | jq .mitigation_impact'
curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$VULN/probe.php?format=json" \
  | python3 -c '
import json,sys
d=json.load(sys.stdin)
site = d["mitigation_impact"][0]
print("  site:", site["site"], "| forms:", site["forms_found"])
for o in site["options"]:
    if o["id"]=="block_multipart":
        for b in o["blocks"]:
            print("  ", b["confidence"], b["purpose"], "|", b["file"].split("/html/")[-1])
'

# 断言：三档都在、A 能给出目标版本、B 找到表单、C 明说不管 109618
m=$(curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$VULN/probe.php?format=json" | python3 -c '
import json,sys
d=json.load(sys.stdin)
ids=[o["id"] for o in d["mitigation_impact"][0]["options"]]
print(",".join(ids))')
check "三档处置齐全" "upgrade_php,block_multipart,disable_upload_progress" "$m"

tgt=$(curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$VULN/probe.php?format=json" \
  | python3 -c 'import json,sys;print([o for o in json.load(sys.stdin)["mitigation_impact"][0]["options"] if o["id"]=="upgrade_php"][0]["to_version"])')
check "A 档给出目标版本" 8.5.12 "$tgt"

nb=$(curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$VULN/probe.php?format=json" \
  | python3 -c 'import json,sys;print(len([o for o in json.load(sys.stdin)["mitigation_impact"][0]["options"] if o["id"]=="block_multipart"][0]["blocks"]))')
check "B 档找到预置表单数" 4 "$nb"

nc=$(curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$VULN/probe.php?format=json" \
  | python3 -c 'import json,sys;o=[x for x in json.load(sys.stdin)["mitigation_impact"][0]["options"] if x["id"]=="disable_upload_progress"][0];print(len(o["does_not_cover"]))')
check "C 档声明不管的事（含 109618）" 2 "$nc"

# B 档不得把工具自身当成上传表单（回归项）
self_hit=$(curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$VULN/probe.php?format=json" \
  | python3 -c 'import json,sys;b=[o for o in json.load(sys.stdin)["mitigation_impact"][0]["options"] if o["id"]=="block_multipart"][0]["blocks"];print(sum(1 for x in b if x["file"].endswith("probe.php")))')
check "B 档不误报工具自身" 0 "$self_hit"

sec "13. 8.5.12 靶场必须如实报出 Chain A 仍为风险（不许报全绿）"
echo '# 预置了 app/view.php（间接式 LFI：$tpl = $_GET[...]; include $tpl）与 app/download.php（直接式 readfile）'
docker exec pea-lab-fixed sh -c 'ls /var/www/html/app/ 2>/dev/null || echo "(no app dir)"'
echo
echo '$ curl :18092/probe.php?format=json   # 8.5.12，已被官方修复'
curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$FIXED/probe.php?format=json" \
  | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("tier        :", d["tier"], "/", d["tier_label"])
print("tier_reason :", d["tier_reason"])
for k,v in d["axes"].items():
    print("  %-24s %-16s %s" % (k, v["state"], v["detail"][:70]))
'

t=$(curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$FIXED/probe.php?format=json" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["tier"])')
check "8.5.12 不得判为全绿" orange "$t"

pst=$(curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$FIXED/probe.php?format=json" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["axes"]["patch_composition"]["state"])')
check "patch_composition 判出无 PR#22113" pr22113_absent "$pst"

lf=$(curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$FIXED/probe.php?format=json" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["axes"]["lfi_exposure"]["state"])')
check "lfi_exposure 抓到落点（含间接式）" sink_found "$lf"

sec "14. session.upload_progress 开/关对照（这一轴读的是真配置，不是硬编码）"
# 用同一份 php.ini 只改这一行，起一个 18095 的对照容器。
OFFINI="$(cd .. && pwd)/.tmpini/php-off.ini"
OFFWEB="$(cd .. && pwd)/.tmpupoff"
mkdir -p "$(cd .. && pwd)/.tmpini"
sed 's/^session.upload_progress.enabled = On/session.upload_progress.enabled = Off/' \
  ./php.ini > "$OFFINI"
rm -rf "$OFFWEB"; mkdir -p "$OFFWEB"; cp -R ./webroot/. "$OFFWEB"/; chmod -R a+rX "$OFFWEB"
docker rm -f pea-upoff >/dev/null 2>&1
sleep 1
echo '$ docker run --name pea-upoff -p 18095:80 （只为这一行关掉 upload_progress）'
# 不要吞掉 docker run 的输出：上一次这里把「端口还没从上一个转发里释放」的错误
# 全丢了，只表现为后面 JSON 解析失败，查了半天。
RUN_OUT=$(docker run -d --name pea-upoff -p 18095:80 \
  -v "$OFFWEB":/var/www/html \
  -v "$OFFINI":/usr/local/etc/php/php.ini:ro \
  -v "$(cd .. && pwd)/probe.php":/opt/probe.php:ro \
  -e PHP_EXPOSURE_AUDIT_TOKEN="$TOKEN" \
  docker.m.daocloud.io/library/php:8.5.12-apache \
  bash -c 'cp /opt/probe.php /var/www/html/probe.php && chmod 644 /var/www/html/probe.php && apache2-foreground' 2>&1)
if [ $? -ne 0 ]; then
  printf '  docker run 失败: %s\n' "$RUN_OUT"
fi

# 等它真的能应答，不是盲 sleep。
UP=0
for _i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 2
  if [ "$(curl -s -m 3 -o /dev/null -w '%{http_code}' -H "X-Audit-Token: $TOKEN" http://127.0.0.1:18095/probe.php)" = "200" ]; then
    UP=1; break
  fi
done
if [ "$UP" != 1 ]; then
  printf '  %s\n' '  pea-upoff 起不来，容器日志：'
  docker logs pea-upoff 2>&1 | tail -6 | sed 's/^/    /'
fi

echo '$ docker exec pea-upoff php -r "echo ini_get(\"session.upload_progress.enabled\");"'
docker exec pea-upoff php -r 'echo "  ini_get=", var_export(ini_get("session.upload_progress.enabled"), true), "\n";'

up_on=$(curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:$FIXED/probe.php?format=json" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["axes"]["upload_progress"]["state"])')
up_off=$(curl -s -m 30 -H "X-Audit-Token: $TOKEN" "http://127.0.0.1:18095/probe.php?format=json" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["axes"]["upload_progress"]["state"])')
check "开了 upload_progress → enabled"  enabled  "$up_on"
check "关了 upload_progress → disabled" disabled "$up_off"

echo '# 收尾'
docker rm -f pea-upoff >/dev/null 2>&1
rm -rf "$OFFWEB" "$OFFINI"
echo '  pea-upoff 已删除，临时 ini / webroot 已清理'

sec "15. 没有 PHP 的机器必须报「未发现 PHP」+ exit 2（假阴性回归项）"
echo '# 这里曾经是个硬伤：total=0 落进 else，被判成 patched → 输出「版本已在修复线以上」+ exit 0。'
echo '# 一个会说「你安全」的工具，在最常见的场景（扫错机器 / 容器在别的 host）里骗人。'
echo
echo '$ docker exec pea-nophp bash /opt/pea/audit.sh --no-docker'
docker rm -f pea-nophp >/dev/null 2>&1
docker run -d --name pea-nophp -v "$(cd .. && pwd)":/opt/pea:ro \
  docker.m.daocloud.io/library/debian:bookworm-slim bash -c 'sleep 300' >/dev/null 2>&1
sleep 3
NORES=$(docker exec pea-nophp bash /opt/pea/audit.sh --no-docker 2>&1)
printf '%s\n' "$NORES" | head -4
docker exec pea-nophp bash /opt/pea/audit.sh --no-docker >/dev/null 2>&1
NOEXIT=$?

nl=$(printf '%s\n' "$NORES" | head -1)
check "首行是「未发现 PHP」" "未发现 PHP" "$nl"
check "退出码 2（不是 0）" 2 "$NOEXIT"

# JSON 里 not_applicable 必须与 unknown 区分开，且有 targets_found
nj=$(docker exec pea-nophp bash /opt/pea/audit.sh --no-docker --json 2>/dev/null)
nv=$(printf '%s' "$nj" | python3 -c 'import json,sys;print(json.load(sys.stdin)["verdict"])' 2>/dev/null)
nt=$(printf '%s' "$nj" | python3 -c 'import json,sys;print(json.load(sys.stdin)["targets_found"])' 2>/dev/null)
check "JSON verdict = not_applicable" not_applicable "$nv"
check "JSON targets_found = 0" 0 "$nt"

# --no-docker 且什么都没找到 → 必须提示可能漏了 docker
if printf '%s' "$nj" | grep -q 'no-docker'; then
  check "--no-docker 时提示可能漏了 docker" yes yes
else
  check "--no-docker 时提示可能漏了 docker" yes no
fi

docker rm -f pea-nophp >/dev/null 2>&1
echo '  pea-nophp 已删除'

hr
printf '结果: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ] || exit 1
