#!/usr/bin/env bash
# ==============================================================================
# audit.sh — PHP 暴露面自查 (CVE-2026-109618 / CVE-2026-109619)
# version 0.1.0
#
# 只读工具：不写配置、不改文件、不发任何网络请求。
# 唯一的写操作是 $TMPDIR 下的临时目录，退出时删除。
#
# 用法:
#   ./audit.sh                     人类可读报告（先结论后细节）
#   ./audit.sh --json              只输出 JSON（可管道）
#   ./audit.sh --root /data/www    追加要扫的 webroot（可重复）
#   ./audit.sh --no-scan           跳过 webroot 覆盖链扫描（快）
#   ./audit.sh --no-docker         跳过 docker 容器检查
#   ./audit.sh --docker-only       只查 docker 容器
#   ./audit.sh --explain           额外打印判定依据
#   ./audit.sh --no-mitigation     跳过三档处置代价评估（不扫表单）
#   ./audit.sh --mitigation        显式开启三档处置评估（默认已开）
#   ssh host 'bash -s' < audit.sh  远程跑（不需要拷贝文件）
#
# 退出码: 0 = 已修/不中   1 = 受影响   2 = 无法判定
#
# 判定只依赖三件事：版本号区间、发行版 backport 证据、二进制 patch 标记。
# 三者冲突时输出 unknown，不猜。
# ==============================================================================
set -uo pipefail

TOOL_NAME='php-exposure-audit'
TOOL_COMPONENT='audit.sh'
TOOL_VERSION='0.1.0'
SCHEMA_VERSION='1.0'

ADV_MIN='5.4.0'
ADV_MAX='8.5.11'
FIX_82='8.2.35'
FIX_83='8.3.36'
FIX_84='8.4.27'
FIX_85='8.5.12'

# patch 里新增的内部符号。出现在二进制里 = 源码树至少是打过补丁的。
MARKER_SYM='php_basic_early_rinit'
MARKER_SYM2='zend_handle_delayed_oom'
# 这个符号任何一个正常 PHP 二进制都有；它不在 = 被 strip 了，标记缺失不能当证据
CONTROL_SYM='php_request_shutdown'

INI_KEYS='session.upload_progress.enabled
session.upload_progress.cleanup
post_max_size
upload_max_filesize
memory_limit
fatal_error_backtraces
session.use_only_cookies
session.serialize_handler
opcache.enable'

OUT_JSON=0
SCAN_WEBROOTS=1
DO_DOCKER=1
DOCKER_ONLY=0
EXPLAIN=0
VERBOSE=0
MITIGATIONS=1
MAX_FILES=20000
EXTRA_ROOTS=''
WARNINGS=''

# ------------------------------------------------------------------ util ----
log()  { [ "$OUT_JSON" = 1 ] && printf '%s\n' "$*" >&2 || printf '%s\n' "$*"; }
# 警告一律先攒着，不立刻往 stderr 打。
# 理由是输出契约：合并 stderr 时，立即打印的警告会抢在结论前面，
# 让「第一行必须是结论」这条失效。文本模式在报告末尾统一渲染，
# JSON 模式 stdout 必须干净，所以那时才走 stderr。
warn() {
	WARNINGS="${WARNINGS}$*
"
	if [ "$OUT_JSON" = 1 ]; then
		printf 'warning: %s\n' "$*" >&2
	fi
}
vlog() { [ "$VERBOSE" = 1 ] && printf '  · %s\n' "$*" >&2 || true; }

jstr() {
	local s=$1
	s=${s//\\/\\\\}
	s=${s//\"/\\\"}
	s=${s//$'\n'/\\n}
	s=${s//$'\t'/\\t}
	s=${s//$'\r'/\\r}
	printf '"%s"' "$s"
}

ver_num() {
	local v a b c rest
	v=${1%%[-+~]*}
	a=${v%%.*}
	rest=${v#*.}
	b=${rest%%.*}
	c=${rest#*.}
	c=${c%%.*}
	case $a in ''|*[!0-9]*) a=0 ;; esac
	case $b in ''|*[!0-9]*) b=0 ;; esac
	case $c in ''|*[!0-9]*) c=0 ;; esac
	printf '%s' $((a * 1000000 + b * 1000 + c))
}

# -1 / 0 / 1
vcmp() {
	local x y
	x=$(ver_num "$1"); y=$(ver_num "$2")
	if [ "$x" -lt "$y" ]; then printf '%s' -1
	elif [ "$x" -gt "$y" ]; then printf '%s' 1
	else printf '%s' 0; fi
}

to_bytes() {
	local v n unit
	v=$(printf '%s' "$1" | tr -d ' ' | tr 'a-z' 'A-Z')
	case $v in ''|'0') printf '%s' 0; return ;; '-1') printf '%s' -1; return ;; esac
	unit=${v: -1}
	case $unit in
		K|M|G) n=${v%?} ;;
		*)     unit=''; n=$v ;;
	esac
	case $n in ''|*[!0-9]*) printf '%s' -1; return ;; esac
	case $unit in
		K) printf '%s' $((n * 1024)) ;;
		M) printf '%s' $((n * 1024 * 1024)) ;;
		G) printf '%s' $((n * 1024 * 1024 * 1024)) ;;
		*) printf '%s' "$n" ;;
	esac
}

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
	cat <<'USAGE'
audit.sh — PHP 暴露面自查 (CVE-2026-109618 / CVE-2026-109619)

只读工具：不写配置、不改文件、不发任何网络请求。
唯一的写操作是 $TMPDIR 下的临时目录，退出时删除。

用法:
  ./audit.sh                     人类可读报告（先结论后细节）
  ./audit.sh --json              只输出 JSON（可管道）
  ./audit.sh --root /data/www    追加要扫的 webroot（可重复）
  ./audit.sh --no-scan           跳过 webroot 覆盖链扫描（快）
  ./audit.sh --no-docker         跳过 docker 容器检查
  ./audit.sh --docker-only       只查 docker 容器
  ./audit.sh --explain           额外打印判定依据
  ./audit.sh -v                  详细日志到 stderr
  ssh host 'bash -s' < audit.sh  远程跑（不需要拷贝文件）

退出码: 0 = 已修/不中   1 = 受影响   2 = 无法判定

判定只依赖三件事：版本号区间、发行版 backport 证据、二进制 patch 标记。
三者冲突时输出 unknown，不猜。
USAGE
}

# ------------------------------------------------------------------ args ----
while [ $# -gt 0 ]; do
	case $1 in
		--json)        OUT_JSON=1 ;;
		--no-scan)     SCAN_WEBROOTS=0 ;;
		--no-docker)   DO_DOCKER=0 ;;
		--docker-only) DO_DOCKER=1; DOCKER_ONLY=1 ;;
		--no-docker-only) DOCKER_ONLY=0 ;;
		--explain)     EXPLAIN=1 ;;
		--mitigation)      MITIGATIONS=1 ;;
		--no-mitigation)   MITIGATIONS=0 ;;
		--verbose|-v)  VERBOSE=1 ;;
		--root)        EXTRA_ROOTS="${EXTRA_ROOTS}${2:?}:"; shift ;;
		--max-files)   MAX_FILES=${2:?}; shift ;;
		--version)     printf '%s %s\n' "$TOOL_NAME" "$TOOL_VERSION"; exit 0 ;;
		-h|--help)     usage; exit 0 ;;
		*) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 3 ;;
	esac
	shift
done

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/php-exposure-audit.XXXXXX") || exit 3
trap 'rm -rf "$TMPD"' EXIT INT TERM

RECS="$TMPD/recs"
mkdir -p "$RECS"
OVR_FILE="$TMPD/overrides.tsv"
: > "$OVR_FILE"
MP_DIR="$TMPD/mitigation"
mkdir -p "$MP_DIR"
SITES_FILE="$TMPD/sites.tsv"
: > "$SITES_FILE"

# -------------------------------------------------------------- classify ----
# $1 = version  ->  "verdict<TAB>reason"
classify_version() {
	local v=$1 br fix
	br=${v%.*}
	case $br in
		8.2) fix=$FIX_82 ;;
		8.3) fix=$FIX_83 ;;
		8.4) fix=$FIX_84 ;;
		8.5) fix=$FIX_85 ;;
		*)   fix='' ;;
	esac
	if [ -n "$fix" ] && [ "$(vcmp "$v" "$fix")" -ge 0 ]; then
		printf 'patched\tversion_at_or_above_branch_fix:%s\n' "$fix"; return
	fi
	if [ "$(vcmp "$v" "$ADV_MIN")" -lt 0 ]; then
		printf 'patched\tversion_below_affected_range\n'; return
	fi
	if [ "$(vcmp "$v" "$ADV_MAX")" -le 0 ]; then
		printf 'affected\tversion_in_vulnerable_range\n'; return
	fi
	printf 'unknown\tversion_above_advisory_range:%s\n' "$v"
}

is_eol_branch() {
	case ${1%.*} in
		5.*|7.0|7.1|7.2|7.3|7.4|8.0|8.1) return 0 ;;
		*) return 1 ;;
	esac
}

# ---------------------------------------------------------------- sources ----
pkg_info() {
	local bin=$1 mgr='' name='' ver=''
	if have dpkg-query; then
		local line
		line=$(dpkg-query -S "$bin" 2>/dev/null | head -1)
		if [ -n "$line" ]; then
			mgr='dpkg'
			name=${line%%:*}
			ver=$(dpkg-query -W -f='${Version}' "$name" 2>/dev/null)
		fi
	fi
	if [ -z "$mgr" ] && have rpm; then
		local q
		q=$(rpm -qf "$bin" 2>/dev/null | head -1)
		if [ -n "$q" ] && [ "${q#file }" = "$q" ] && [ "${q#*not owned*}" = "$q" ]; then
			mgr='rpm'
			name="$q"
			ver=$(rpm -q --queryformat '%{VERSION}-%{RELEASE}' "$q" 2>/dev/null)
		fi
	fi
	printf '%s\t%s\t%s\n' "${mgr:-none}" "$name" "$ver"
}

# $1 = package manager, $2 = package name
changelog_hit() {
	local mgr=$1 name=$2 d f
	[ -n "$name" ] && [ "$mgr" != 'none' ] || return 1
	if [ "$mgr" = 'dpkg' ]; then
		for d in /usr/share/doc/"$name" /usr/share/doc/"${name%:*}"*; do
			[ -d "$d" ] || continue
			for f in "$d"/changelog.Debian.gz "$d"/changelog.gz; do
				[ -r "$f" ] || continue
				if gzip -dc "$f" 2>/dev/null | head -80 | grep -qiE 'CVE-2026-10961[89]'; then
					printf '%s\n' "$f"; return 0
				fi
			done
		done
	elif [ "$mgr" = 'rpm' ]; then
		if rpm -q --changelog "$name" 2>/dev/null | head -80 | grep -qiE 'CVE-2026-10961[89]'; then
			printf 'rpm-changelog:%s\n' "$name"; return 0
		fi
	fi
	return 1
}

# $1 = binary path -> list of php shared objects / binaries worth scanning
php_artifacts() {
	local bin=$1 dir pre
	dir=$(dirname "$bin")
	pre=$(dirname "$dir")
	printf '%s\n' "$bin"
	[ -x "$dir/php-fpm" ]   && printf '%s\n' "$dir/php-fpm"
	[ -x "$dir/php-cgi" ]   && printf '%s\n' "$dir/php-cgi"
	[ -x "$pre/sbin/php-fpm" ] && printf '%s\n' "$pre/sbin/php-fpm"
	[ -x "$pre/bin/php-fpm" ]  && printf '%s\n' "$pre/bin/php-fpm"
	for dir in /usr/lib/apache2/modules /usr/lib64/httpd/modules /usr/lib/httpd/modules \
	           /usr/local/apache/modules /usr/local/apache2/modules /opt/cpanel/*/root/usr/lib/apache2/modules \
	           /www/server/apache/modules /usr/libexec/apache2 "${pre}/lib" "${pre}/lib/apache2/modules"; do
		[ -d "$dir" ] || continue
		ls "$dir"/libphp*.so "$dir"/php*.so 2>/dev/null
	done
	# 只保留真实存在的、大小合理的文件
	:
}

# 返回: present | absent_conclusive | inconclusive
marker_state() {
	local bin=$1 f control=0 marker=0
	local -a files
	files=$(php_artifacts "$bin" | sort -u)
	while IFS= read -r f; do
		[ -r "$f" ] || continue
		# 跳过明显不是 ELF 的（脚本/文本）
		head -c 4 "$f" 2>/dev/null | grep -q 'ELF' || continue
		if grep -aq -- "$CONTROL_SYM" "$f" 2>/dev/null; then
			control=1
			if grep -aq -- "$MARKER_SYM" "$f" 2>/dev/null || grep -aq -- "$MARKER_SYM2" "$f" 2>/dev/null; then
				marker=1
			fi
		fi
	done <<EOF
$files
EOF
	if [ "$marker" = 1 ]; then printf '%s' 'present'; return; fi
	if [ "$control" = 1 ]; then printf '%s' 'absent_conclusive'; return; fi
	printf '%s' 'inconclusive'
}

# -------------------------------------------------------------- sapi det ----
# $1 = php binary -> "available|active|mod_php_loaded"
detect_sapis() {
	local bin=$1 dir pre avail='' active='' modphp=0 f
	dir=$(dirname "$bin"); pre=$(dirname "$dir")

	case $(basename "$bin") in
		*php-fpm*)   avail="$avail fpm" ;;
		*lsphp*)     avail="$avail litespeed" ;;
		*frankenphp*) avail="$avail frankenphp" ;;
		*php-cgi*)   avail="$avail cgi-fcgi" ;;
	esac
	[ -x "$dir/php-fpm" ]           && avail="$avail fpm"
	[ -x "$pre/sbin/php-fpm" ]      && avail="$avail fpm"
	[ -x "$dir/php-cgi" ]           && avail="$avail cgi-fcgi"
	[ -x "$pre/bin/php-cgi" ]       && avail="$avail cgi-fcgi"
	[ -x "$dir/lsphp" ]             && avail="$avail litespeed"
	[ -x "$dir/frankenphp" ]        && avail="$avail frankenphp"

	# mod_php: 找 libphp*.so 是否被 apache 加载
	if [ -d /proc ]; then
		local p exe comm
		for p in /proc/[0-9]*; do
			[ -r "$p/maps" ] || continue
			if grep -qaE '/(libphp[0-9]*\.so|libphp\.so)' "$p/maps" 2>/dev/null; then
				modphp=1; active="$active apache2handler"; break
			fi
		done
		# 只看进程自己的可执行名（/proc/PID/exe）——
		# 不能 grep cmdline 或 ps command：我们自己命令行里就有 "php-fpm" 字样。
		for p in /proc/[0-9]*; do
			exe=$(readlink "$p/exe" 2>/dev/null) || continue
			comm=${exe##*/}
			shopt -s nocasematch 2>/dev/null || true
			case $comm in
				php-fpm*)                  active="$active fpm" ;;
				frankenphp*)               active="$active frankenphp" ;;
				lsphp*|lshttpd|litespeed)  active="$active litespeed" ;;
				php-cgi*)                  active="$active cgi-fcgi" ;;
			esac
			shopt -u nocasematch 2>/dev/null || true
		done
	else
		# 非 Linux（macOS/BSD）：没有 /proc，只能看进程名，
		# 用 ps -eo comm（只列可执行名，不会把 grep 自己算进去）。
		local plist
		plist=$(ps -eo comm 2>/dev/null | sed 's#.*/##' | sort -u)
		printf '%s\n' "$plist" | grep -qx 'php-fpm'      && active="$active fpm"
		printf '%s\n' "$plist" | grep -qx 'frankenphp'   && active="$active frankenphp"
		printf '%s\n' "$plist" | grep -qE '^lsphp|^lshttpd|^litespeed' && active="$active litespeed"
		printf '%s\n' "$plist" | grep -qx 'php-cgi'      && active="$active cgi-fcgi"
	fi

	# apache 模块列表作为交叉验证
	if [ "$modphp" = 0 ]; then
		local m
		for m in apache2ctl apachectl httpd; do
			have "$m" || continue
			if "$m" -M 2>/dev/null | grep -q 'php_module'; then
				modphp=1; active="$active apache2handler"; break
			fi
		done
	fi
	[ "$modphp" = 1 ] && avail="$avail apache2handler"

	printf '%s|%s|%s\n' "$(printf '%s' "$avail" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//')" \
	                   "$(printf '%s' "$active" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//')" \
	                   "$modphp"
}

# --------------------------------------------------------------- ini sets ----
# $1 = binary, $2 = version -> lines "sapi<TAB>ini_file<TAB>scan_dir"
find_ini_sets() {
	local bin=$1 ver=$2 d
	local short=${ver%.*}
	# Docker 官方镜像 / 手工编译
	[ -f /usr/local/etc/php/php.ini ] && printf 'generic\t%s\t%s\n' /usr/local/etc/php/php.ini /usr/local/etc/php/conf.d
	[ -d /usr/local/etc/php/conf.d ] && [ ! -f /usr/local/etc/php/php.ini ] && printf 'generic\t(none)\t%s\n' /usr/local/etc/php/conf.d
	# Debian / Ubuntu
	for d in cli fpm apache2 cgi; do
		[ -f "/etc/php/$short/$d/php.ini" ] && printf '%s\t%s\t%s\n' "$d" "/etc/php/$short/$d/php.ini" "/etc/php/$short/$d/conf.d"
	done
	[ -f "/etc/php/$ver/cli/php.ini" ] && printf 'cli\t%s\t%s\n' "/etc/php/$ver/cli/php.ini" "/etc/php/$ver/cli/conf.d"
	# RHEL / CentOS / Remi
	[ -f /etc/php.ini ] && printf 'generic\t%s\t%s\n' /etc/php.ini /etc/php.d
	# cPanel EA4
	for d in /opt/cpanel/ea-php*/root; do
		[ -d "$d" ] || continue
		[ -f "$d/etc/php.ini" ] && printf 'cpanel\t%s\t%s\n' "$d/etc/php.ini" "$d/etc/php.d"
	done
	# 宝塔
	for d in /www/server/php/*/etc; do
		[ -d "$d" ] || continue
		[ -f "$d/php.ini" ] && printf 'bt\t%s\t%s\n' "$d/php.ini" "$d/php.d"
	done
	# oneinstack / lnmp
	[ -f /usr/local/php/etc/php.ini ] && printf 'oneinstack\t%s\t%s\n' /usr/local/php/etc/php.ini /usr/local/php/etc/php.d
	for d in /usr/local/php[0-9]*/etc; do
		[ -d "$d" ] || continue
		[ -f "$d/php.ini" ] && printf 'oneinstack\t%s\t%s\n' "$d/php.ini" "$d/php.d"
	done
	# LiteSpeed
	for d in /usr/local/lsws/lsphp*/etc/php/*; do
		[ -d "$d" ] || continue
		[ -f "$d/php.ini" ] && printf 'litespeed\t%s\t%s\n' "$d/php.ini" "$d/conf.d"
	done
	# Homebrew / macOS
	for d in /opt/homebrew/etc/php/* /usr/local/etc/php/*; do
		[ -d "$d" ] || continue
		[ -f "$d/php.ini" ] && printf 'brew\t%s\t%s\n' "$d/php.ini" "$d/conf.d"
	done
}

# $1 = bin, $2 = ini file or (none), $3 = scan dir, $4 = keys -> "k=v" lines
read_ini_values() {
	local bin=$1 ini=$2 scan=$3 keys=$4
	local args=()
	[ -n "$ini" ] && [ "$ini" != '(none)' ] && args=(-c "$ini")
	# bash 3.2 + set -u：空数组展开会报 unbound variable，
	# 所以用 ${args[@]+...} 这种写法。
	if [ -n "$scan" ] && [ "$scan" != '(none)' ]; then
		PHP_INI_SCAN_DIR="$scan" "$bin" ${args[@]+"${args[@]}"} -r '
			$keys = explode("\n", $argv[1]);
			foreach ($keys as $k) { if ($k === "") continue; $v = ini_get($k); echo $k, "=", ($v === false ? "" : $v), "\n"; }
		' -- "$keys" 2>/dev/null
	else
		PHP_INI_SCAN_DIR='' "$bin" ${args[@]+"${args[@]}"} -r '
			$keys = explode("\n", $argv[1]);
			foreach ($keys as $k) { if ($k === "") continue; $v = ini_get($k); echo $k, "=", ($v === false ? "" : $v), "\n"; }
		' -- "$keys" 2>/dev/null
	fi
}

# ------------------------------------------------------------- overrides ----
# 收集 webroot 列表
collect_webroots() {
	local r
	{
		printf '%s\n' /var/www/html /var/www /usr/share/nginx/html /srv/www /data/www
		ls -d /www/wwwroot/* 2>/dev/null
		ls -d /home/*/public_html 2>/dev/null
		ls -d /var/www/vhosts/*/httpdocs 2>/dev/null
		# apache DocumentRoot
		if have apache2ctl; then apache2ctl -S 2>/dev/null | sed -n 's/.*documentroot: *//Ip'; fi
		if have httpd; then httpd -S 2>/dev/null | sed -n 's/.*documentroot: *//Ip'; fi
		# nginx root
		if [ -d /etc/nginx ]; then
			grep -rhE '^[[:space:]]*root[[:space:]]+[^;]+;' /etc/nginx 2>/dev/null \
				| sed -E 's/^[[:space:]]*root[[:space:]]+//; s/;.*//'
		fi
		printf '%s' "$EXTRA_ROOTS" | tr ':' '\n'
	} | grep -v '^$' | sort -u
}

scan_overrides() {
	local roots count=0 root
	roots=$(collect_webroots)
	: > "$OVR_FILE"
	while IFS= read -r root; do
		[ -d "$root" ] || continue
		case $root in /proc*|/sys*|/dev*) continue ;; esac
		count=$((count + 1))
		[ "$count" -gt 40 ] && break
		find "$root" -maxdepth 6 \( -name .htaccess -o -name .user.ini -o -name php.ini -o -name .php.ini \) \
			-type f -readable 2>/dev/null | head -"$MAX_FILES" | while IFS= read -r f; do
			grep -nEi '^[[:space:]]*;?[[:space:]]*(php_value|php_flag|php_admin_value|php_admin_flag|session\.upload_progress\.enabled|post_max_size|upload_max_filesize|memory_limit|fatal_error_backtraces)' "$f" 2>/dev/null \
				| grep -v '^[0-9]*:[[:space:]]*;' \
				| while IFS=: read -r ln rest; do
					printf '%s\t%s\t%s\n' "$f" "$ln" "$rest"
				done
		done >> "$OVR_FILE"
	done <<EOF
$roots
EOF
	# 去重（同一文件被多个 root 扫到）
	if [ -s "$OVR_FILE" ]; then
		sort -u "$OVR_FILE" -o "$OVR_FILE" 2>/dev/null || true
	fi
}

# 一行覆盖是否削弱了缓解措施
override_effect() {
	local line=$1 low
	low=$(printf '%s' "$line" | tr 'A-Z' 'a-z')
	case $low in
		*session.upload_progress.enabled*)
			case $low in
				*'= 0'*|*'=0'*|*' off'*|*'false'*) printf 'ok' ;;
				*) printf 'weakens' ;;
			esac ;;
		*fatal_error_backtraces*)
			case $low in
				*'= 0'*|*'=0'*|*' off'*|*'false'*) printf 'ok' ;;
				*) printf 'weakens' ;;
			esac ;;
		*post_max_size*|*upload_max_filesize*|*memory_limit*)
			printf 'raises' ;;
		*) printf 'neutral' ;;
	esac
}

# ------------------------------------------------------- mitigation ----
# 三档处置的代价评估（mitigation_impact）。
#
# B 档只读文件系统里的模板/表单，不发任何请求、不触发任何漏洞路径。
# 猜不出用途就写「疑似上传」，不编造功能名。
MP_MAX_FILES=${MP_MAX_FILES:-3000}

guess_purpose() {
	local low
	low=$(printf '%s %s' "$1" "$2" | tr 'A-Z' 'a-z')
	case $low in
		*wp-admin/async-upload*|*wp-admin/media-new*|*plupload*) printf 'WordPress 媒体库上传' ;;
		*avatar*|*头像*)          printf '头像上传' ;;
		*product*|*商品*)         printf '商品图上传' ;;
		*cart*|*checkout*|*结账*) printf '结账/购物车（可能带附件）' ;;
		*resume*|*简历*)          printf '简历上传' ;;
		*gallery*|*album*|*相册*) printf '相册/图片上传' ;;
		*logo*)                   printf 'Logo 上传' ;;
		*attach*|*附件*)          printf '附件上传' ;;
		*import*|*导入*)          printf '数据导入（可能走 multipart）' ;;
		*ticket*|*工单*)          printf '工单附件上传' ;;
		*kyc*|*idcard*|*证件*)    printf '证件/实名认证上传' ;;
		*invoice*|*发票*)         printf '发票上传' ;;
		*banner*)                 printf 'Banner 上传' ;;
		*cover*|*封面*)           printf '封面图上传' ;;
		*editor*|*编辑器*)        printf '富文本编辑器附件' ;;
		*profile*|*个人资料*)     printf '个人资料表单（可能含头像）' ;;
		*media*|*媒体*)           printf '媒体文件上传' ;;
		*upload*|*上传*)          printf '上传接口' ;;
		*) printf '' ;;
	esac
}

# $1 = root, $2 = forms out, $3 = endpoints out
scan_multipart_site() {
	local root=$1 out=$2 epout=$3 f ln line kind conf purpose detail low base
	: > "$out"
	: > "$epout"
	[ -d "$root" ] || { printf 'NODIR\t%s\n' "$root" >> "$out"; return 1; }

	while IFS= read -r f; do
		[ -r "$f" ] || continue
		# 工具自身的源码里就含有 "multipart/form-data" / "<input type=file" 这些字符串
		# （它们就是匹配规则本身），不排掉的话会被自己报成一个上传表单。
		# 按内容标记排，不按文件名 —— 用户 webroot 里可能真的有个叫 probe.php 的业务文件。
		if grep -qF 'php-exposure-audit' "$f" 2>/dev/null; then
			continue
		fi
		# 一个文件里可能有好几个表单，但也可能同一表单既有 enctype 又有 <input type=file>。
		# 规则：
		#   有 multipart enctype → 按 enctype 行报，每个表单一条；
		#   没 enctype 但有 file input → 只报第一条（说明它可能靠 JS 拼请求）。
		# 这样同一个表单不会被数两次。
		local has_enc=0 n_enc=0 first_js='' first_input=''
		n_enc=$(grep -cEi 'enctype=[^ >]*multipart/form-data' "$f" 2>/dev/null)
		[ -z "$n_enc" ] && n_enc=0
		if [ "$n_enc" -gt 0 ]; then
			has_enc=1
			grep -nEi 'enctype=[^ >]*multipart/form-data' "$f" 2>/dev/null | head -6 \
			| while IFS=: read -r ln line; do
				[ -z "$ln" ] && continue
				low=$(printf '%s' "$line" | tr 'A-Z' 'a-z')
				conf='medium'
				# 同一个文件里还有 file input → 基本坐实是上传表单
				case $low in
					*'<input'*file*) conf='high' ;;
					*) [ "$(grep -cEi '<input[^>]*type=[^ >]*file' "$f" 2>/dev/null)" -gt 0 ] && conf='high' ;;
				esac
				detail=$(printf '%s' "$line" | sed 's/^[[:space:]]*//' | cut -c1-160)
				purpose=$(guess_purpose "$f" "$detail")
				[ -z "$purpose" ] && purpose='疑似上传（路径和字段名都看不出用途）'
				printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "$ln" 'form_multipart' "$conf" "$purpose" "$detail" >> "$out"
			done
		fi

		# 没有 enctype 的：file input / FormData / WordPress 上传入口
		if [ "$has_enc" = 0 ]; then
			local hit
			hit=$(grep -nEi '<input[^>]*type=[^ >]*file|new FormData\(|wp-admin/(async-upload|media-new)\.php' "$f" 2>/dev/null | head -1)
			[ -z "$hit" ] && continue
			ln=${hit%%:*}
			line=${hit#*:}
			low=$(printf '%s' "$line" | tr 'A-Z' 'a-z')
			case $low in
				*wp-admin/async-upload*|*wp-admin/media-new*) kind='wp_media'; conf='high' ;;
				*'new formdata('*)                            kind='formdata_js'; conf='low' ;;
				*'<input'*file*)                              kind='input_file'; conf='medium' ;;
				*) continue ;;
			esac
			detail=$(printf '%s' "$line" | sed 's/^[[:space:]]*//' | cut -c1-160)
			purpose=$(guess_purpose "$f" "$detail")
			[ -z "$purpose" ] && purpose='疑似上传（路径和字段名都看不出用途）'
			printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "$ln" "$kind" "$conf" "$purpose" "$detail" >> "$out"
		fi
	done < <(find "$root" -maxdepth 8 -type f \
		\( -name '*.php' -o -name '*.html' -o -name '*.htm' -o -name '*.twig' \
		   -o -name '*.tpl' -o -name '*.jsp' -o -name '*.asp' -o -name '*.aspx' \
		   -o -name '*.vue' -o -name '*.jsx' -o -name '*.tsx' -o -name '*.js' \) \
		-size -512k 2>/dev/null \
		| grep -vE '/(node_modules|vendor|\.git|bower_components)/' \
		| head -"$MP_MAX_FILES")

	# 只看文件名像上传接口的（不当成确认命中，只当线索）
	find "$root" -maxdepth 8 -type f \
		\( -name '*upload*' -o -name '*Upload*' -o -name '*attach*' -o -name 'media-new.php' \) \
		-size -512k 2>/dev/null \
		| grep -vE '/(node_modules|vendor|\.git)/' | head -40 \
		| while IFS= read -r f; do
			grep -qF "$f" "$out" 2>/dev/null && continue
			base=${f##*/}
			purpose=$(guess_purpose "$f" "$base")
			[ -z "$purpose" ] && purpose='疑似上传接口（文件名像，但没找到表单）'
			printf '%s\t0\tupload_endpoint\tlow\t%s\t%s\n' "$f" "$purpose" "$base" >> "$epout"
		done
	return 0
}

# $1 = version -> "target<TAB>note"
mit_target() {
	local ver=$1 br fix
	br=${ver%.*}
	case $br in
		8.2) fix=$FIX_82 ;;
		8.3) fix=$FIX_83 ;;
		8.4) fix=$FIX_84 ;;
		8.5) fix=$FIX_85 ;;
		*)   fix='' ;;
	esac
	if [ -n "$fix" ]; then
		if [ "$(vcmp "$ver" "$fix")" -lt 0 ]; then
			printf '%s\t升级到同分支修复版；不改代码、不改配置。\n' "$fix"
		else
			printf '%s\t已在这条分支的修复线以上，无需升级。\n' "$fix"
		fi
		return
	fi
	if is_eol_branch "$ver"; then
		printf '8.2.35\t分支 %s 官方已停支（EOL）：需发行版 backport 或 TuxCare ELS，否则升到 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 之一。\n' "${ver%.*}"
		return
	fi
	printf 'unknown\t版本 %s 不在公告区间内，给不出目标版本。\n' "$ver"
}

render_mitigation_site() {
	local root=$1 forms=$2 eps=$3 ver=$4
	local hits=0 ephits=0 trunc='' f ln kind conf purpose detail tgt note

	printf '\n--- 处置选项（三档代价）· %s ---\n' "$root"

	# ---- A ----
	printf 'A. 升级 PHP\n'
	if [ -n "$ver" ]; then
		IFS=$'\t' read -r tgt note <<EOF
$(mit_target "$ver")
EOF
		printf '   %s → %s\n' "$ver" "$tgt"
		printf '   %s\n' "$note"
	else
		printf '   没有可用的 PHP 版本（判不了）。\n'
	fi
	printf '   代价：不改代码、不改配置。唯一完整修复。\n'

	# ---- B ----
	if [ -s "$forms" ]; then
		hits=$(grep -vcE '^(TRUNC|NODIR)	' "$forms" 2>/dev/null)
		[ -z "$hits" ] && hits=0
		grep -qE '^TRUNC	' "$forms" 2>/dev/null && trunc=1
	fi
	if [ -s "$eps" ]; then
		ephits=$(grep -vc '^$' "$eps" 2>/dev/null)
		[ -z "$ephits" ] && ephits=0
	fi

	printf 'B. Web 层 403 multipart\n'
	if [ -s "$forms" ] && grep -qE '^NODIR	' "$forms" 2>/dev/null; then
		printf '   判不了：目录不可读。\n'
	elif [ "$hits" -eq 0 ] && [ "$ephits" -eq 0 ]; then
		printf '   没找到 multipart 表单。\n'
		printf '   判不了的地方：纯 API / SPA 站点可能用 JS 动态拼请求，静态扫不到。\n'
		printf '   若确认站内没有上传功能，403 multipart 的代价接近零。\n'
	else
		if [ "$hits" -gt 0 ]; then
			printf '   代价：下面这些功能会全废（%s 处）\n' "$hits"
			local shown=0
			while IFS=$'\t' read -r f ln kind conf purpose detail; do
				case $f in TRUNC|NODIR) continue ;; esac
				[ -z "$f" ] && continue
				shown=$((shown + 1))
				[ "$shown" -gt 12 ] && continue
				printf '     [%s] %s:%s  %s\n' "$conf" "${f#"$root"}" "$ln" "$purpose"
				printf '          %s\n' "$detail"
			done < "$forms"
			[ "$hits" -gt 12 ] && printf '     ...（还有 %s 处，用 --json 拿全量）\n' $((hits - 12))
		fi
		if [ "$ephits" -gt 0 ]; then
			printf '   另外这些文件名像上传接口（未确认是否 multipart，不当成已确认）：\n'
			local eshown=0
			while IFS=$'\t' read -r f ln kind conf purpose detail; do
				[ -z "$f" ] && continue
				eshown=$((eshown + 1))
				[ "$eshown" -gt 8 ] && continue
				printf '     %s  %s\n' "${f#"$root"}" "$purpose"
			done < "$eps"
			[ "$ephits" -gt 8 ] && printf '     ...（还有 %s 个）\n' $((ephits - 8))
		fi
		[ -n "$trunc" ] && printf '   注意：文件数超过 %s，扫描被截断，可能还有没扫到的表单。\n' "$MP_MAX_FILES"
	fi

	# ---- C ----
	printf 'C. 只关 session.upload_progress%s\n' "$([ -n "$ver" ] && [ "$(vcmp "$ver" '8.5.0')" -ge 0 ] && printf '（+ fatal_error_backtraces）')"
	printf '   治：CVE-2026-109619 的 session 注入路径。\n'
	printf '   不治：CVE-2026-109618（Zend 引擎 OOM）—— 这条跟 upload_progress 无关，\n'
	printf '         任何超大 multipart POST 都能触发。\n'
	if [ -n "$ver" ] && [ "$(vcmp "$ver" '8.5.0')" -ge 0 ]; then
		printf '   8.5.x 还要一起关 fatal_error_backtraces=0（第三条臂）。\n'
	fi
	printf '   代价：大多数应用不用 upload_progress，关掉一般无感。\n'
	printf '         但如果覆盖链里有 .htaccess / .user.ini 把它又打开，先清掉。\n'
}

render_mitigation_all() {
	[ "$MITIGATIONS" = 1 ] && [ "$SCAN_WEBROOTS" = 1 ] || return 0
	local site root tsv eps
	if [ ! -s "$SITES_FILE" ]; then
		printf '\n--- 处置选项 ---\n没找到任何站点目录，三档代价都判不了。\n'
		printf '用 --root 指定 webroot 再跑一次。\n'
		return 0
	fi
	while IFS=$'\t' read -r site root; do
		[ -z "$site" ] && continue
		tsv="$MP_DIR/$site.tsv"
		eps="$MP_DIR/$site.ep.tsv"
		render_mitigation_site "$root" "$tsv" "$eps" "$MIT_VER"
	done < "$SITES_FILE"
}

mitigation_json() {
	local firsts=1 site root tsv eps hits=0 ephits=0 tgt note
	printf '"mitigation_impact":['
	if [ -s "$SITES_FILE" ]; then
		while IFS=$'\t' read -r site root; do
			[ -z "$site" ] && continue
			tsv="$MP_DIR/$site.tsv"
			eps="$MP_DIR/$site.ep.tsv"
			hits=0
			[ -s "$tsv" ] && hits=$(grep -vcE '^(TRUNC|NODIR)	' "$tsv" 2>/dev/null)
			[ -z "$hits" ] && hits=0
			ephits=0
			[ -s "$eps" ] && ephits=$(grep -vc '^$' "$eps" 2>/dev/null)
			[ -z "$ephits" ] && ephits=0

			[ "$firsts" = 1 ] || printf ','
			firsts=0
			printf '{"site":%s,"forms_found":%s,"endpoints_suspected":%s,"options":[' \
				"$(jstr "$root")" "$hits" "$ephits"

			# A
			printf '{"id":"upgrade_php","title":"升级 PHP","cost":"low",'
			if [ -n "$MIT_VER" ]; then
				IFS=$'\t' read -r tgt note <<EOF
$(mit_target "$MIT_VER")
EOF
				printf '"from_version":%s,"to_version":%s,"note":%s,' \
					"$(jstr "$MIT_VER")" "$(jstr "$tgt")" "$(jstr "$note")"
			else
				printf '"from_version":null,"to_version":null,"note":"没有可用的 PHP 版本",'
			fi
			printf '"blocks":[],"notes":["不改代码、不改配置","唯一完整修复"]},'

			# B
			printf '{"id":"block_multipart","title":"Web 层 403 multipart","cost":"high",'
			printf '"blocks":['
			local bf=1 f ln kind conf purpose detail
			if [ -s "$tsv" ]; then
				while IFS=$'\t' read -r f ln kind conf purpose detail; do
					case $f in TRUNC|NODIR) continue ;; esac
					[ -z "$f" ] && continue
					[ "$bf" = 1 ] || printf ','
					bf=0
					printf '{"file":%s,"line":%s,"kind":%s,"confidence":%s,"purpose":%s,"evidence":%s}' \
						"$(jstr "$f")" "$ln" "$(jstr "$kind")" "$(jstr "$conf")" "$(jstr "$purpose")" "$(jstr "$detail")"
				done < "$tsv"
			fi
			printf '],"suspected_endpoints":['
			local ef=1
			if [ -s "$eps" ]; then
				while IFS=$'\t' read -r f ln kind conf purpose detail; do
					[ -z "$f" ] && continue
					[ "$ef" = 1 ] || printf ','
					ef=0
					printf '{"path":%s,"purpose":%s,"confidence":%s}' \
						"$(jstr "$f")" "$(jstr "$purpose")" "$(jstr "$conf")"
				done < "$eps"
			fi
			printf '],'
			if [ "$hits" -eq 0 ] && [ "$ephits" -eq 0 ]; then
				printf '"limitation":"没找到 multipart 表单；纯 API / SPA 用 JS 动态拼请求时静态扫不到",'
			else
				printf '"limitation":null,'
			fi
			printf '"notes":["不发起任何请求，只读文件","403 掉 multipart 会同时废掉商品图/结账等上传"]},'

			# C
			printf '{"id":"disable_upload_progress","title":"只关 session.upload_progress","cost":"low",'
			printf '"covers":["CVE-2026-109619 的 session 注入路径"],'
			printf '"does_not_cover":["CVE-2026-109618（Zend 引擎 OOM，与 upload_progress 无关）"'
			if [ -n "$MIT_VER" ] && [ "$(vcmp "$MIT_VER" '8.5.0')" -ge 0 ]; then
				printf ',"8.5.x 的 fatal_error_backtraces 臂（需单独设 0）"'
			fi
			printf '],'
			printf '"blocks":[],"notes":["不是完整修复","覆盖链里的 .htaccess / .user.ini 可能把它重新打开"]}'
			printf ']}'
		done < "$SITES_FILE"
	fi
	printf ']'
}

# ============================================================== axes ======
# 多轴判定。
#
# 单看版本号会给出两种错误答案：
#   1. 版本够新 → 报「安全」，但 Chain A 的写原语是设计如此，压根没修
#   2. 版本够新 → 报「安全」，但 PR#22113（session fixation 守卫）从未合并
#
# 所以这里每一项独立检查、独立输出，最后再由这些项算一个 tier。
# 严禁把「version 达标」当成整体结论。

# PR#22113：rfc1867 FORMDATA 分支里的 !PS(use_only_cookies) 守卫。
# 截至 2026-10-22 仍是 open / 未合并，8.5.12 里没有。
PR22113_EVIDENCE='session fixation|rfc1867|22113|use_only_cookies|upload_progress.*(fix|guard)'

# 官方修复版里都不含 PR#22113（除非发行版单独 backport）
is_official_fix_version() {
	case $1 in
		"$FIX_82"|"$FIX_83"|"$FIX_84"|"$FIX_85") return 0 ;;
	esac
	return 1
}

# 从一个 install 的 ini.tsv 里取「最坏」的一行：任意 SAPI 打开就算打开
# $1 = rd, $2 = key -> value（没有则空）
ini_worst() {
	awk -F'\t' -v k="$2" '$3==k && $4!="" {print $4}' "$1/ini.tsv" 2>/dev/null \
		| sort -u | grep -vE '^(0|off|Off|OFF|false|no|)$' | head -1
}

bool_ini_on() {
	case $1 in ''|0|off|false|no|Off|OFF|False) return 1 ;; *) return 0 ;; esac
}

# ---- patch_composition ------------------------------------------------
# 判「这个构建有没有 PR#22113 等价修复」。
# 只认两类证据：
#   a) changelog 里明确提到 session fixation / rfc1867 / 22113 / use_only_cookies
#   b) 上游官方修复版（已知不含）→ 明确判 absent，不猜
# 其余一律 unknown，绝不默认成「已修」。
# $1 = rd -> "status<TAB>detail"
patch_composition() {
	local rd=$1 ver mstate pkgmgr pkgname clf evid
	ver=$(cat "$rd/version" 2>/dev/null)
	mstate=$(cat "$rd/marker" 2>/dev/null)
	IFS=$'\t' read -r pkgmgr pkgname _ < "$rd/pkg" 2>/dev/null

	# a) 包 changelog 里有没有会话固定相关条目
	clf=$(cat "$rd/changelog" 2>/dev/null)
	if [ -n "$clf" ]; then
		case $clf in
			rpm-changelog:*) evid=$(rpm -q --changelog "${clf#rpm-changelog:}" 2>/dev/null | head -120 | grep -iE "$PR22113_EVIDENCE" | head -1) ;;
			*) [ -r "$clf" ] && evid=$(gzip -dc "$clf" 2>/dev/null | head -120 | grep -iE "$PR22113_EVIDENCE" | head -1) ;;
		esac
		if [ -n "$evid" ]; then
			printf 'pr22113_present\tchangelog 命中会话固定相关条目: %s\n' "$(printf '%s' "$evid" | cut -c1-120)"
			return
		fi
	fi

	# b) 上游官方修复版：确定不含（PR 未合并），可以给 absent
	if is_official_fix_version "$ver"; then
		if [ -n "$clf" ]; then
			printf 'pr22113_absent\t%s 是上游修复版，PR#22113 未合并；包 changelog 里也没有会话固定相关条目\n' "$ver"
		else
			printf 'pr22113_absent\t%s 是上游修复版（自编译/官方镜像），PR#22113 未合并，源码里没有该守卫\n' "$ver"
		fi
		return
	fi

	# c) 其它情况不猜
	if [ -z "$pkgname" ] || [ "$pkgmgr" = 'none' ]; then
		printf 'unknown\t自编译或官方镜像，读不到包补丁列表，判不了是否含 PR#22113 等价修复\n'
	else
		printf 'unknown\tchangelog 不可读或不含会话固定条目，无法确认是否 backport 了 PR#22113\n'
	fi
}

# ---- lfi_exposure -----------------------------------------------------
# 静态扫 webroot 里的 LFI 落点。只读文件，不发请求。
# 找不到 ≠ 没有 —— 静态扫描证不了「不存在」。
#
# 直接式：sink 那一行里就有超全局
LFI_DIRECT='(include|require)(_once)?[[:space:]]*\(?[[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|(file_get_contents|readfile|fopen)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)'
# 间接式：sink 用变量（变量是否被污染再单独查）
LFI_INDIRECT='(include|require)(_once)?[[:space:]]*\(?[[:space:]]*\$[A-Za-z_]|(file_get_contents|readfile|fopen)[[:space:]]*\([[:space:]]*\$[A-Za-z_]'

scan_lfi_sinks() {
	local out=$1 root cnt=0 f ln line
	: > "$out"
	[ "$SCAN_WEBROOTS" = 1 ] || return 1
	collect_webroots > "$TMPD/lfi.raw" 2>/dev/null
	# 嵌套根目录去重：/var/www 与 /var/www/html 同时存在时只扫后者，
	# 否则同一个落点会被数两遍，把「2 处」报成「4 处」。
	: > "$TMPD/lfi.roots"
	while IFS= read -r ra; do
		[ -n "$ra" ] || continue
		local keep=1 rb
		while IFS= read -r rb; do
			[ -n "$rb" ] || continue
			[ "$ra" = "$rb" ] && continue
			case $rb in "$ra"/*) keep=0; break ;; esac
		done < "$TMPD/lfi.raw"
		[ "$keep" = 1 ] && printf '%s\n' "$ra" >> "$TMPD/lfi.roots"
	done < "$TMPD/lfi.raw"

	while IFS= read -r root; do
		[ -n "$root" ] && [ -d "$root" ] || continue
		case $root in /proc*|/sys*|/dev*) continue ;; esac
		cnt=$((cnt + 1))
		[ "$cnt" -gt 20 ] && break
		find "$root" -maxdepth 8 -type f -name '*.php' -size -512k -readable 2>/dev/null \
			| grep -vE '/(node_modules|vendor|\.git|bower_components)/' \
			| head -"$MAX_FILES" \
			| while IFS= read -r f; do
				grep -qF 'php-exposure-audit' "$f" 2>/dev/null && continue

				# 1) 直接式
				grep -nEi "$LFI_DIRECT" "$f" 2>/dev/null | head -3 \
					| while IFS=: read -r ln line; do
						printf '%s\t%s\tdirect\t%s\n' "$f" "$ln" \
							"$(printf '%s' "$line" | sed 's/^[[:space:]]*//' | cut -c1-140)"
					done

				# 2) 间接式：sink 用变量，且同文件里该变量来自超全局
				grep -nEi "$LFI_INDIRECT" "$f" 2>/dev/null | head -3 \
					| while IFS=: read -r ln line; do
						local vname taint src
						vname=$(printf '%s' "$line" \
							| sed -nE 's/.*(include|require)(_once)?[[:space:]]*\(?[[:space:]]*(\$[A-Za-z_][A-Za-z0-9_]*).*/\3/p' | head -1)
						[ -z "$vname" ] && vname=$(printf '%s' "$line" | grep -oE '\$[A-Za-z_][A-Za-z0-9_]*' | head -1)
						[ -z "$vname" ] && continue
						taint=$(printf '%s' "$vname" | sed 's/^\$//')
						src=$(grep -nE "\\\$$taint[[:space:]]*=[^=].*\\\$_(GET|POST|REQUEST|COOKIE|FILES)" "$f" 2>/dev/null | head -1)
						[ -z "$src" ] && continue
						printf '%s\t%s\tindirect(%s)\t%s\n' "$f" "$ln" "$vname" \
							"$(printf '%s' "$line" | sed 's/^[[:space:]]*//' | cut -c1-110) <= $(printf '%s' "$src" | cut -c1-80)"
					done
			done >> "$out"
	done < "$TMPD/lfi.roots"
	# 最后去重：同一 文件+行 只留一条
	if [ -s "$out" ]; then
		sort -u "$out" -o "$out" 2>/dev/null || true
	fi
	[ -s "$out" ]
}

# ---- 组装 --------------------------------------------------------------
# $1 = rd -> 写 $rd/axes.tsv + $rd/tier + $rd/tier_label + $rd/tier_reason
compute_axes() {
	local rd=$1
	local ver modphp mstate vstate pstate up bp br opc ser
	local lfi_file="$TMPD/lfi-sinks.tsv"
	local lfi_status lfi_detail ovr_weak

	ver=$(cat "$rd/version" 2>/dev/null)
	modphp=$(cat "$rd/modphp" 2>/dev/null); [ -z "$modphp" ] && modphp=0
	mstate=$(cat "$rd/marker" 2>/dev/null)

	# 1. version
	IFS=$'\t' read -r vstate _ <<EOF
$(classify_version "$ver")
EOF

	# 2. patch_composition
	local pdetail
	IFS=$'\t' read -r pstate pdetail <<EOF
$(patch_composition "$rd")
EOF

	# 3. upload_progress（开着 = 写原语在）
	up=$(ini_worst "$rd" 'session.upload_progress.enabled')

	# 4. lfi_exposure
	if [ ! -f "$lfi_file" ]; then
		scan_lfi_sinks "$lfi_file" 2>/dev/null || true
		[ -f "$lfi_file" ] || : > "$lfi_file"
	fi
	if [ "$SCAN_WEBROOTS" != 1 ]; then
		lfi_status='not_scanned'; lfi_detail='本次跳过了 webroot 扫描（--no-scan），LFI 落点未检查'
	elif [ -s "$lfi_file" ]; then
		lfi_status='sink_found'
		lfi_detail="$(wc -l < "$lfi_file" | tr -d ' ') 处可疑 include/文件读取（静态扫描，需人工确认是否真可控）"
	else
		lfi_status='no_sink_found'
		lfi_detail='静态扫描没找到，但静态扫描证不了「不存在」'
	fi

	# 5. serializer_reset（FPM 跨请求残留）—— OOM 补丁覆盖即修
	ser=$(cat "$rd/sapi_active" 2>/dev/null)
	case $ser in
		*fpm*)
			if [ "$mstate" = 'present' ]; then
				ser='covered'
			elif [ "$mstate" = 'absent_conclusive' ]; then
				ser='leaks'
			else
				ser='unknown'
			fi ;;
		*) ser='not_applicable' ;;
	esac

	# 6. fatal_error_backtraces（仅 8.5.x）
	if [ "$(vcmp "$ver" '8.5.0')" -ge 0 ] 2>/dev/null; then
		bp=$(ini_worst "$rd" 'fatal_error_backtraces')
		if [ -z "$bp" ]; then bp='unknown'
		elif bool_ini_on "$bp"; then bp='on'
		else bp='off'; fi
	else
		bp='not_applicable'
	fi

	# 7. opcache
	opc=$(ini_worst "$rd" 'opcache.enable')
	if [ -z "$opc" ]; then opc='off'
	elif bool_ini_on "$opc"; then
		[ "$mstate" = 'present' ] && opc='covered' || opc='needs_patch'
	else
		opc='off'
	fi

	: > "$rd/axes.tsv"
	printf 'version\t%s\t%s\n'                "$vstate" "$(printf '%s' "$ver")" >> "$rd/axes.tsv"
	printf 'patch_composition\t%s\t%s\n'      "$pstate" "$pdetail" >> "$rd/axes.tsv"
	printf 'upload_progress\t%s\t%s\n'        "$([ -n "$up" ] && echo enabled || echo disabled)" "session.upload_progress.enabled=${up:-0}" >> "$rd/axes.tsv"
	printf 'lfi_exposure\t%s\t%s\n'           "$lfi_status" "站点级（全部 webroot 扫一次）：$lfi_detail" >> "$rd/axes.tsv"
	printf 'serializer_reset\t%s\t%s\n'       "$ser" "FPM 跨请求残留状态（OOM 补丁覆盖即修）" >> "$rd/axes.tsv"
	printf 'fatal_error_backtraces\t%s\t%s\n' "$bp" "仅 8.5.x；须为 0" >> "$rd/axes.tsv"
	printf 'opcache\t%s\t%s\n'                "$opc" "OPcache 共享内存是 109619 里关不掉的一条臂" >> "$rd/axes.tsv"

	# ---- tier ----
	ovr_weak=0
	if [ -s "$OVR_FILE" ]; then
		ovr_weak=$(awk -F'\t' '{print $3}' "$OVR_FILE" 2>/dev/null | while IFS= read -r l; do
			[ "$(override_effect "$l")" = 'weakens' ] && echo x
		done | wc -l | tr -d ' ')
		[ -z "$ovr_weak" ] && ovr_weak=0
	fi

	local tier reason
	case $vstate in
		unknown)
			tier='unknown'; reason='版本无法对照公告区间' ;;
		affected)
			tier='red'; reason='版本在受影响区间且无 backport 证据' ;;
		patched)
			if [ "$lfi_status" = 'sink_found' ]; then
				tier='orange'; reason='版本已修，但站点存在 LFI 落点 —— Chain A 可打，与版本无关'
			elif [ "$pstate" != 'pr22113_present' ]; then
				tier='orange'; reason='版本已修 OOM，但 patch_composition 无 PR#22113 等价修复（session fixation 守卫缺失）'
			elif [ "$ovr_weak" -gt 0 ]; then
				tier='orange'; reason="覆盖链里有 ${ovr_weak} 条会重新削弱缓解措施"
			elif [ "$bp" = 'on' ]; then
				tier='orange'; reason='8.5.x 上 fatal_error_backtraces 仍为开'
			elif [ "$opc" = 'needs_patch' ]; then
				tier='orange'; reason='OPcache 开着且补丁标记缺失'
			elif [ "$lfi_status" = 'not_scanned' ]; then
				tier='orange'; reason='LFI 落点未检查（--no-scan），不能判为缓解到位'
			else
				tier='yellow'; reason='版本已修 + 无 LFI 落点 + PR#22113 等价 + 缓解到位'
			fi ;;
		*)
			tier='unknown'; reason='判定异常' ;;
	esac

	printf '%s' "$tier"   > "$rd/tier"
	printf '%s' "$reason" > "$rd/tier_reason"
	case $tier in
		red)    printf '%s' '未修'             > "$rd/tier_label" ;;
		orange) printf '%s' '已修但有残留'      > "$rd/tier_label" ;;
		yellow) printf '%s' '已修且缓解到位'    > "$rd/tier_label" ;;
		*)      printf '%s' '判不了'            > "$rd/tier_label" ;;
	esac
}

# ---------------------------------------------------------------- docker ----
# $1 = blob (\n 换成 | ), $2 = key -> value
docker_row_get() {
	printf '%s' "$1" | tr '|' '\n' | sed -n "s/^$2=//p" | head -1
}

# 容器里的 PHP 也要参与判定，不能只列出来
# $1 = ver, $2 = marker(present/absent/空) -> "verdict<TAB>reason"
docker_verdict() {
	local ver=$1 marker=$2 base v r
	[ -z "$ver" ] && { printf 'unknown\tcontainer_php_version_unparseable'; return; }
	IFS=$'\t' read -r v r <<EOF
$(classify_version "$ver")
EOF
	case "$v:$r" in
		affected:version_in_vulnerable_range)
			if [ "$marker" = 'present' ]; then
				printf 'patched\tbackport_marker_present'
			else
				printf 'affected\tversion_in_vulnerable_range'
			fi ;;
		*) printf '%s\t%s' "$v" "$r" ;;
	esac
}

docker_installs() {
	have docker || { warn 'docker 命令不存在，跳过容器检查'; return; }
	docker info >/dev/null 2>&1 || { warn 'docker 守护进程不可达，跳过容器检查'; return; }
	local ids id img
	ids=$(docker ps --format '{{.ID}}' 2>/dev/null)
	[ -z "$ids" ] && return
	while IFS= read -r id; do
		[ -z "$id" ] && continue
		img=$(docker inspect -f '{{.Config.Image}}' "$id" 2>/dev/null)
		local out
		out=$(docker exec -i "$id" sh -s 2>/dev/null <<'COLLECT'
b=$(command -v php 2>/dev/null || true)
[ -n "$b" ] || exit 3
printf 'BIN=%s\n' "$b"
printf 'VER=%s\n' "$(php -r 'echo PHP_VERSION;' 2>/dev/null)"
printf 'SAPI=%s\n' "$(php -r 'echo PHP_SAPI;' 2>/dev/null)"
for k in session.upload_progress.enabled session.upload_progress.cleanup post_max_size upload_max_filesize memory_limit fatal_error_backtraces session.use_only_cookies session.serialize_handler opcache.enable; do
	printf 'INI.%s=%s\n' "$k" "$(php -r "echo ini_get('$k');" 2>/dev/null)"
done
printf 'INI_FILE=%s\n' "$(php --ini 2>/dev/null | sed -n 's/^Loaded Configuration File: *//p')"
printf 'SCAN_DIR=%s\n' "$(php --ini 2>/dev/null | sed -n 's/^Scan for additional .ini files in: *//p')"
printf 'BUILD=%s\n' "$(php -i 2>/dev/null | sed -n 's/^Build Date => *//p')"
printf 'FPM=%s\n' "$(command -v php-fpm 2>/dev/null)"
printf 'CGI=%s\n' "$(command -v php-cgi 2>/dev/null)"
mp=0
for p in /proc/[0-9]*; do
	[ -r "$p/maps" ] || continue
	if grep -qaE '/(libphp[0-9]*\.so|libphp\.so)' "$p/maps" 2>/dev/null; then mp=1; break; fi
done
printf 'MODPHP=%s\n' "$mp"
printf 'MARKER=%s\n' "$(grep -qa php_basic_early_rinit /usr/lib/apache2/modules/libphp.so 2>/dev/null && echo present || echo absent)"
COLLECT
)
		[ -z "$out" ] && continue
		printf '%s\t%s\t%s\n' "$id" "$img" "$(printf '%s' "$out" | tr '\n' '|')" >> "$TMPD/docker.tsv"
	done <<EOF
$ids
EOF
}

# ------------------------------------------------------------ per install ----
# $1 = rec dir, $2 = php binary, $3 = realpath
collect_install() {
	local rd=$1 bin=$2 real=$3
	local ver sapi_all sapi_avail sapi_act modphp pkgmgr pkgnm pkgver
	local mstate clhit confidence verdict reason

	ver=$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null)
	if [ -z "$ver" ]; then
		ver=$(printf '%s' "$("$bin" -v 2>/dev/null | head -1)" | sed -n 's/^PHP \([0-9][0-9.]*\).*/\1/p')
	fi
	[ -z "$ver" ] && return 1

	printf '%s' "$ver" > "$rd/version"
	printf '%s' "$bin" > "$rd/bin"
	printf '%s' "$real" > "$rd/real"
	printf '%s' "$("$bin" -r 'echo PHP_SAPI;' 2>/dev/null)" > "$rd/cli_sapi"
	printf '%s' "$("$bin" -r 'echo PHP_OS;' 2>/dev/null)" > "$rd/os"
	printf '%s' "$("$bin" -r 'echo zend_version();' 2>/dev/null)" > "$rd/zend"
	printf '%s' "$("$bin" -r 'echo PHP_INT_SIZE === 8 ? "64" : "32";' 2>/dev/null)" > "$rd/bits"

	IFS=$'\t' read -r pkgmgr pkgnm pkgver <<EOF
$(pkg_info "$bin")
EOF
	printf '%s\t%s\t%s\n' "$pkgmgr" "$pkgnm" "$pkgver" > "$rd/pkg"

	IFS='|' read -r sapi_avail sapi_act modphp <<EOF
$(detect_sapis "$bin")
EOF
	printf '%s' "${sapi_avail:-cli}" > "$rd/sapi_avail"
	printf '%s' "${sapi_act:-}" > "$rd/sapi_active"
	printf '%s' "${modphp:-0}" > "$rd/modphp"

	mstate=$(marker_state "$real")
	printf '%s' "$mstate" > "$rd/marker"

	if clhit=$(changelog_hit "$pkgmgr" "$pkgnm" 2>/dev/null); then
		printf '%s' "$clhit" > "$rd/changelog"
	else
		: > "$rd/changelog"
	fi

	# ---- 判定 ----
	IFS=$'\t' read -r verdict reason <<EOF
$(classify_version "$ver")
EOF

	# backport / 冲突处理
	if [ "$verdict" = 'affected' ]; then
		if [ "$mstate" = 'present' ]; then
			verdict='patched'; reason='backport_marker_present'
		elif [ -s "$rd/changelog" ]; then
			if [ "$mstate" = 'absent_conclusive' ]; then
				# 包说修了、二进制说没修 → 不猜
				verdict='unknown'; reason='conflicting_evidence_changelog_says_patched_binary_lacks_marker'
			else
				verdict='patched'; reason='package_changelog_mentions_cve'
			fi
		fi
	fi
	if [ "$verdict" = 'patched' ] && [ "$reason" = 'backport_marker_present' ] && [ -s "$rd/changelog" ]; then
		reason='backport_marker_present_and_changelog_confirms'
	fi

	case $verdict in
		affected)
			if [ "$mstate" = 'absent_conclusive' ] && [ ! -s "$rd/changelog" ]; then confidence='high'
			elif [ "$mstate" = 'inconclusive' ] || [ -s "$rd/changelog" ]; then confidence='medium'
			else confidence='medium'; fi ;;
		patched)
			case $reason in
				version_at_or_above_branch_fix|version_below_affected_range) confidence='high' ;;
				*) confidence='medium' ;;
			esac ;;
		*) confidence='low' ;;
	esac

	printf '%s' "$verdict"  > "$rd/verdict"
	printf '%s' "$reason"   > "$rd/reason"
	printf '%s' "$confidence" > "$rd/confidence"

	if is_eol_branch "$ver" && [ "$verdict" != 'patched' ]; then
		printf '分支 %s 已 EOL，官方无补丁（仅社区 backport）\n' "${ver%.*}" >> "$rd/notes"
	fi
	if [ "$modphp" = 1 ]; then
		printf 'mod_php 已加载：应用代码未执行即可触发（Chain D），优先级最高\n' >> "$rd/notes"
	fi
	[ "$mstate" = 'inconclusive' ] && printf '二进制被 strip 或读不到，patch 标记无法作为证据\n' >> "$rd/notes"

	# ---- ini ----
	: > "$rd/ini.tsv"
	local sets ini_file scan_dir sapi
	sets=$(find_ini_sets "$bin" "$ver")
	if [ -z "$sets" ]; then
		local cliini
		cliini=$("$bin" --ini 2>/dev/null)
		ini_file=$(printf '%s\n' "$cliini" | sed -n 's/^Loaded Configuration File: *//p')
		scan_dir=$(printf '%s\n' "$cliini" | sed -n 's/^Scan for additional .ini files in: *//p')
		sets=$(printf 'cli\t%s\t%s\n' "${ini_file:-(none)}" "${scan_dir:-(none)}")
	fi
	while IFS=$'\t' read -r sapi ini_file scan_dir; do
		[ -z "$sapi" ] && continue
		read_ini_values "$bin" "$ini_file" "$scan_dir" "$INI_KEYS" | while IFS= read -r kv; do
			printf '%s\t%s\t%s\t%s\n' "$sapi" "$ini_file" "${kv%%=*}" "${kv#*=}"
		done >> "$rd/ini.tsv"
		printf '%s\t%s\t%s\n' "$sapi" "${ini_file:-(none)}" "${scan_dir:-(none)}" >> "$rd/ini_sources.tsv"
	done <<EOF
$sets
EOF
	[ -s "$rd/ini.tsv" ] || printf 'cli\t(none)\tpost_max_size\t\n' > "$rd/ini.tsv"

	# 8.5+ 才有 fatal_error_backtraces
	if [ "$(vcmp "$ver" '8.5.0')" -lt 0 ]; then
		printf 'fatal_error_backtraces 在 8.5 以下不存在，跳过\n' >> "$rd/notes"
	fi

	# ---- build date ----
	"$bin" -i 2>/dev/null | sed -n 's/^Build Date => *//p' | head -1 > "$rd/build_date" || : > "$rd/build_date"

	# ---- findings ----
	: > "$rd/findings.tsv"
	if [ "${modphp:-0}" = 1 ]; then
		printf 'sapi.mod_php\tcritical\tmod_php 已加载\tmod_php 下 OOM 触发链（Chain D）在应用代码执行前完成，任何 PHP 端点都是入口。这一项优先级最高。\n' >> "$rd/findings.tsv"
	fi
	local fk fval fst fopc
	for fk in session.upload_progress.enabled fatal_error_backtraces; do
		fval=$(awk -F'\t' -v k="$fk" '$3==k {print $4; exit}' "$rd/ini.tsv" 2>/dev/null)
		[ -z "$fval" ] && continue
		fst=$(ini_state "$fk" "$fval")
		[ "$fst" = 'weak' ] || continue
		if [ "$fk" = 'session.upload_progress.enabled' ]; then
			printf 'ini.upload_progress_on\thigh\tsession.upload_progress.enabled 是开着的\t当前值 %s。关掉它能砍掉 CVE-2026-109619 的会话注入面，但挡不住 CVE-2026-109618 的 OOM 链。\n' "$fval" >> "$rd/findings.tsv"
		else
			printf 'ini.fatal_error_backtraces_on\thigh\tfatal_error_backtraces 是开着的（8.5 分支特有）\t8.5.x 上这条是 CVE-2026-109619 的第三条臂（backtrace arm）。设为 0。\n' >> "$rd/findings.tsv"
		fi
	done
	fopc=$(awk -F'\t' '$3=="opcache.enable" {print $4; exit}' "$rd/ini.tsv" 2>/dev/null)
	if [ "$fopc" = '1' ] || [ "$fopc" = 'On' ] || [ "$fopc" = 'on' ]; then
		printf 'opcache.enabled\tinfo\tOPcache 开着\tOPcache 共享内存是 CVE-2026-109619 里没有 INI 开关能关掉的一条臂，只能靠打补丁。\n' >> "$rd/findings.tsv"
	fi
}

# ------------------------------------------------------------- rendering ----
json_install() {
	local rd=$1
	local ver bin real verdict reason conf modphp
	ver=$(cat "$rd/version"); bin=$(cat "$rd/bin"); real=$(cat "$rd/real")
	verdict=$(cat "$rd/verdict"); reason=$(cat "$rd/reason"); conf=$(cat "$rd/confidence")
	modphp=$(cat "$rd/modphp")

	printf '{'
	printf '"binary":%s,' "$(jstr "$bin")"
	printf '"binary_real":%s,' "$(jstr "$real")"
	printf '"version":%s,' "$(jstr "$ver")"
	printf '"version_branch":%s,' "$(jstr "${ver%.*}")"
	printf '"cli_sapi":%s,' "$(jstr "$(cat "$rd/cli_sapi")")"
	printf '"zend_version":%s,' "$(jstr "$(cat "$rd/zend")")"
	printf '"build_date":%s,' "$(jstr "$(cat "$rd/build_date")")"
	IFS=$'\t' read -r pkgmgr pkgnm pkgver < "$rd/pkg"
	printf '"package":{"manager":%s,"name":%s,"version":%s},' "$(jstr "$pkgmgr")" "$(jstr "$pkgnm")" "$(jstr "$pkgver")"
	printf '"verdict":%s,' "$(jstr "$verdict")"
	printf '"verdict_reason":%s,' "$(jstr "$reason")"
	printf '"confidence":%s,' "$(jstr "$conf")"
	printf '"backport":{"marker_state":%s,"package_changelog":%s},' \
		"$(jstr "$(cat "$rd/marker")")" "$(jstr "$(cat "$rd/changelog" 2>/dev/null)")"
	printf '"sapis":{"available":%s,"active":%s,"mod_php":%s},' \
		"$(jstr "$(cat "$rd/sapi_avail")")" "$(jstr "$(cat "$rd/sapi_active")")" "$modphp"

	printf '"ini":{'
	local firstk=1 sapi ini k v
	while IFS=$'\t' read -r sapi ini k v; do
		[ -z "$k" ] && continue
		[ "$firstk" = 1 ] || printf ','
		firstk=0
		printf '%s:{"value":%s,"source":%s}' "$(jstr "$k")" "$(jstr "$v")" "$(jstr "$sapi:$ini")"
	done < "$rd/ini.tsv"
	printf '},'

	printf '"ini_sources":['
	local firsts=1
	if [ -s "$rd/ini_sources.tsv" ]; then
		while IFS=$'\t' read -r sapi ini scan; do
			[ "$firsts" = 1 ] || printf ','
			firsts=0
			printf '{"sapi":%s,"ini_file":%s,"scan_dir":%s}' "$(jstr "$sapi")" "$(jstr "$ini")" "$(jstr "$scan")"
		done < "$rd/ini_sources.tsv"
	fi
	printf '],'

	# ---- 多轴判定（七轴 + tier）----
	# 放在 notes 之前，让人先看到「哪几项过、哪几项不过」再看备注。
	printf '"tier":%s,"tier_label":%s,"tier_reason":%s,' \
		"$(jstr "$(cat "$rd/tier" 2>/dev/null)")" \
		"$(jstr "$(cat "$rd/tier_label" 2>/dev/null)")" \
		"$(jstr "$(cat "$rd/tier_reason" 2>/dev/null)")"

	printf '"axes":{'
	local firsta=1 an av ad
	if [ -s "$rd/axes.tsv" ]; then
		while IFS=$'\t' read -r an av ad; do
			[ -z "$an" ] && continue
			[ "$firsta" = 1 ] || printf ','
			firsta=0
			printf '%s:{"state":%s,"detail":%s}' "$(jstr "$an")" "$(jstr "$av")" "$(jstr "$ad")"
		done < "$rd/axes.tsv"
	fi
	printf '},'

	printf '"notes":['
	local firstn=1
	if [ -s "$rd/notes" ]; then
		while IFS= read -r n; do
			[ -z "$n" ] && continue
			[ "$firstn" = 1 ] || printf ','
			firstn=0
			printf '%s' "$(jstr "$n")"
		done < "$rd/notes"
	fi
	printf '],'

	printf '"findings":['
	local firstf=1 fid sev ftitle fdetail
	if [ -s "$rd/findings.tsv" ]; then
		while IFS=$'\t' read -r fid sev ftitle fdetail; do
			[ -z "$fid" ] && continue
			[ "$firstf" = 1 ] || printf ','
			firstf=0
			printf '{"id":%s,"severity":%s,"title":%s,"detail":%s}' \
				"$(jstr "$fid")" "$(jstr "$sev")" "$(jstr "$ftitle")" "$(jstr "$fdetail")"
		done < "$rd/findings.tsv"
	fi
	printf ']'
	printf '}'
}

ini_advice() {
	# $1 key, $2 value -> echo "建议值" or empty
	case $1 in
		session.upload_progress.enabled) printf '0' ;;
		fatal_error_backtraces)          printf '0' ;;
		*) printf '' ;;
	esac
}

ini_state() {
	# $1 key, $2 value -> ok | weak | info
	local k=$1 v=$2 lv
	lv=$(printf '%s' "$v" | tr 'A-Z' 'a-z')
	case $k in
		session.upload_progress.enabled)
			case $lv in ''|0|off|false|no) printf 'ok' ;; *) printf 'weak' ;; esac ;;
		fatal_error_backtraces)
			case $lv in ''|0|off|false|no) printf 'ok' ;; *) printf 'weak' ;; esac ;;
		memory_limit)
			case $lv in -1) printf 'ok' ;;
				*) if [ "$(to_bytes "$v")" -gt 0 ] && [ "$(to_bytes "$v")" -le 134217728 ]; then printf 'info'; else printf 'ok'; fi ;;
			esac ;;
		*) printf 'info' ;;
	esac
}

render_text_install() {
	local rd=$1 idx=$2 total=$3
	local ver bin verdict reason conf modphp tier tierlabel
	ver=$(cat "$rd/version"); bin=$(cat "$rd/bin")
	verdict=$(cat "$rd/verdict"); reason=$(cat "$rd/reason"); conf=$(cat "$rd/confidence")
	modphp=$(cat "$rd/modphp")
	tier=$(cat "$rd/tier" 2>/dev/null); tierlabel=$(cat "$rd/tier_label" 2>/dev/null)

	printf '\n--- [%s/%s] PHP %s   %s ---\n' "$idx" "$total" "$ver" "$bin"
	if [ -n "$tierlabel" ]; then
		case $tier in
			red)    printf '结论        : %s\n' "$tierlabel" ;;
			orange) printf '结论        : %s\n' "$tierlabel" ;;
			yellow) printf '结论        : %s\n' "$tierlabel" ;;
			*)      printf '结论        : 判不了\n' ;;
		esac
		printf '原因        : %s\n' "$(cat "$rd/tier_reason" 2>/dev/null)"
	else
		case $verdict in
			affected) printf '结论        : 未修 (%s)\n' "$conf" ;;
			patched)  printf '结论        : 已修 (%s)\n' "$conf" ;;
			*)        printf '结论        : 判不了 (%s)\n' "$conf" ;;
		esac
		printf '判定依据    : %s\n' "$reason"
	fi

	# 多轴逐项输出 —— 每一项独立，不许被版本号盖过去
	if [ -s "$rd/axes.tsv" ]; then
		printf '七轴检查    :\n'
		local an av ad mark
		while IFS=$'\t' read -r an av ad; do
			[ -z "$an" ] && continue
			case $av in
				pr22113_present|covered|disabled|no_sink_found|off|not_applicable|patched|below_affected)
					mark='ok' ;;
				red|affected|leaks|on|enabled|sink_found|needs_patch|pr22113_absent)
					mark='!!' ;;
				*) mark='??' ;;
			esac
			printf '  %-2s %-24s %-18s %s\n' "$mark" "$an" "$av" "$ad"
		done < "$rd/axes.tsv"
	fi

	printf '版本判定    : %s (%s)\n' "$verdict" "$reason"
	printf 'backport    : marker=%s' "$(cat "$rd/marker")"
	if [ -s "$rd/changelog" ]; then printf '  changelog=%s\n' "$(cat "$rd/changelog")"; else printf '  changelog=未命中\n'; fi
	printf 'SAPI        : 可用[%s]  运行中[%s]%s\n' "$(cat "$rd/sapi_avail")" "$(cat "$rd/sapi_active")" \
		"$([ "$modphp" = 1 ] && printf '   <<< mod_php')"
	printf '构建时间    : %s\n' "$(cat "$rd/build_date")"

	printf '关键 ini    :\n'
	local first=1
	if [ -s "$rd/ini_sources.tsv" ]; then
		while IFS=$'\t' read -r sapi ini scan; do
			printf '  [%s] %s\n' "$sapi" "$ini"
		done < "$rd/ini_sources.tsv"
	fi
	local k v st adv shown
	while IFS=$'\t' read -r sapi ini k v; do
		[ -z "$k" ] && continue
		st=$(ini_state "$k" "$v")
		adv=$(ini_advice "$k")
		# 空值有两种原因，不能混为一谈：
		#   a) 这个 PHP 版本根本没有这个指令（8.5 之前的 fatal_error_backtraces）
		#   b) 指令存在但扩展没加载（opcache.* 在没编 OPcache 的构建里读不到）
		# 把 b 说成「本版本无此指令」是错的，会让人以为不用管。
		if [ -z "$v" ]; then
			if [ "$k" = 'fatal_error_backtraces' ] && [ "$(vcmp "$ver" '8.5.0')" -lt 0 ]; then
				printf '    %-34s = --%12s (本版本无此指令)\n' "$k" ''
			else
				printf '    %-34s = --%12s (未加载或不可用)\n' "$k" ''
			fi
			continue
		fi
		case $st in
			weak) printf '    %-34s = %-12s (建议 %s)  << 弱\n' "$k" "$v" "$adv" ;;
			*)    printf '    %-34s = %-12s\n' "$k" "$v" ;;
		esac
	done < "$rd/ini.tsv"

	if [ -s "$rd/notes" ]; then
		printf '备注        :\n'
		while IFS= read -r n; do [ -n "$n" ] && printf '  - %s\n' "$n"; done < "$rd/notes"
	fi
	if [ -s "$rd/findings.tsv" ]; then
		printf '发现项      :\n'
		local fid sev ftitle fdetail
		while IFS=$'\t' read -r fid sev ftitle fdetail; do
			[ -z "$fid" ] && continue
			printf '  [%s] %s\n         %s\n' "$sev" "$ftitle" "$fdetail"
		done < "$rd/findings.tsv"
	fi
	if [ "$EXPLAIN" = 1 ]; then
		printf '原始证据    : package=%s\n' "$(cat "$rd/pkg")"
	fi
}

render_overrides() {
	[ "$SCAN_WEBROOTS" = 1 ] || return 0
	local n=0 weak=0 shown=0 f ln line eff trimmed
	if [ ! -s "$OVR_FILE" ]; then
		printf '\n--- 覆盖链 ---\n未发现 .htaccess / .user.ini / php.ini 里的 PHP 指令覆盖\n'
		return
	fi
	n=$(wc -l < "$OVR_FILE" | tr -d ' ')
	printf '\n--- 覆盖链 ---\n共 %s 条 per-directory PHP 指令\n' "$n"
	while IFS=$'\t' read -r f ln line; do
		eff=$(override_effect "$line")
		[ "$eff" = 'weakens' ] && weak=$((weak + 1))
		shown=$((shown + 1))
		[ "$shown" -gt 60 ] && continue
		trimmed=$(printf '%s' "$line" | sed 's/^[[:space:]]*//')
		printf '  %s:%s  %s  [%s]\n' "$f" "$ln" "$trimmed" "$eff"
	done < "$OVR_FILE"
	[ "$n" -gt 60 ] && printf '  ...（还有 %s 条，用 --json 拿全量）\n' $((n - 60))
	if [ "$weak" -gt 0 ]; then
		printf '其中 %s 条会把 session.upload_progress / fatal_error_backtraces 重新打开\n' "$weak"
	fi
}

# ------------------------------------------------------------------ main ----
main() {
	local hostname os kernel now
	hostname=$(hostname 2>/dev/null || printf unknown)
	os=$(uname -s 2>/dev/null || printf unknown)
	kernel=$(uname -r 2>/dev/null || printf unknown)
	now=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)

	if [ "$OUT_JSON" = 0 ]; then
		: # 第一行留给结论
	fi

	# ---- 发现 PHP ----
	local cand="$TMPD/cand.txt"
	: > "$cand"
	if [ "$DOCKER_ONLY" = 0 ]; then
		{
			local n
			for n in php php5 php7 php8 php-cgi php-fpm lsphp frankenphp; do
				command -v "$n" 2>/dev/null
			done
			ls -d /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php /usr/local/bin/php[0-9]* \
			      /usr/local/php*/bin/php /usr/local/php[0-9]*/bin/php \
			      /opt/cpanel/ea-php*/root/usr/bin/php \
			      /opt/remi/php*/root/usr/bin/php \
			      /www/server/php/*/bin/php \
			      /usr/local/lsws/lsphp*/bin/lsphp \
			      /opt/alt/php*/usr/bin/php \
			      /opt/homebrew/bin/php /opt/homebrew/opt/php*/bin/php \
			      /usr/local/opt/php*/bin/php \
			      /Applications/MAMP/bin/php/php*/bin/php 2>/dev/null
			# 有界 find 兜底
			local root
			for root in /opt /usr/local /www /home /srv; do
				[ -d "$root" ] || continue
				find "$root" -maxdepth 5 -type f -name 'php' -perm -u+x 2>/dev/null | head -30
			done
		} | while IFS= read -r p; do
			[ -n "$p" ] || continue
			[ -x "$p" ] || continue
			case $p in *phpize*|*php-config*|*phpdbg*) continue ;; esac
			# 必须真能跑
			"$p" -r 'echo PHP_VERSION;' >/dev/null 2>&1 || continue
			printf '%s\n' "$p"
		done | while IFS= read -r p; do
			readlink -f "$p" 2>/dev/null || printf '%s\n' "$p"
		done | sort -u >> "$cand"
	fi

	# ---- docker ----
	: > "$TMPD/docker.tsv"
	if [ "$DO_DOCKER" = 1 ]; then docker_installs; fi

	# ---- 逐安装采集 ----
	local total=0 i=0 bin real rd
	if [ -s "$cand" ]; then
		while IFS= read -r real; do
			[ -n "$real" ] || continue
			total=$((total + 1))
			rd="$RECS/r$total"
			mkdir -p "$rd"
			: > "$rd/notes"
			: > "$rd/ini_sources.tsv"
			if ! collect_install "$rd" "$real" "$real"; then
				rm -rf "$rd"
				total=$((total - 1))
				continue
			fi
			printf '%s\n' "$rd" >> "$RECS/index"
		done < "$cand"
	fi

	# ---- 覆盖链（全局，一次）----
	[ "$SCAN_WEBROOTS" = 1 ] && scan_overrides

	# ---- LFI 落点（站点级，一次）----
	# 必须早于 compute_axes：Chain A 的判定要靠它。
	if [ "$SCAN_WEBROOTS" = 1 ]; then
		scan_lfi_sinks "$TMPD/lfi-sinks.tsv" 2>/dev/null || true
	else
		: > "$TMPD/lfi-sinks.tsv"
	fi

	# ---- 多轴判定（每个 install 一次）----
	# 放在覆盖链和 LFI 之后，因为 tier 要用到这两项。
	if [ -s "$RECS/index" ]; then
		while IFS= read -r rd; do
			compute_axes "$rd"
		done < "$RECS/index"
	fi

	# ---- 处置选项（三档代价）：扫站点里的 multipart 表单 ----
	# 只读文件系统，不发任何请求。
	MIT_VER=''
	if [ -s "$RECS/index" ]; then
		while IFS= read -r rd; do
			if [ "$(cat "$rd/verdict")" = 'affected' ]; then
				MIT_VER=$(cat "$rd/version")
				break
			fi
		done < "$RECS/index"
		if [ -z "$MIT_VER" ]; then
			rd=$(head -1 "$RECS/index")
			[ -n "$rd" ] && MIT_VER=$(cat "$rd/version" 2>/dev/null)
		fi
	fi
	: > "$SITES_FILE"
	if [ "$MITIGATIONS" = 1 ] && [ "$SCAN_WEBROOTS" = 1 ]; then
		collect_webroots > "$TMPD/webroots.txt" 2>/dev/null
		# /var/www 和 /var/www/html 同时命中时会扫两遍，同一表单报两次。
		# 先去掉嵌套：如果 A 是 B 的祖先，只留 B（更具体的那个）。
		: > "$TMPD/webroots.dedup.txt"
		local a b keep
		while IFS= read -r a; do
			[ -n "$a" ] || continue
			keep=1
			while IFS= read -r b; do
				[ -n "$b" ] || continue
				[ "$a" = "$b" ] && continue
				case $b in
					"$a"/*) keep=0; break ;;   # a 是 b 的祖先 → 丢掉 a
				esac
			done < "$TMPD/webroots.txt"
			[ "$keep" = 1 ] && printf '%s\n' "$a" >> "$TMPD/webroots.dedup.txt"
		done < "$TMPD/webroots.txt"

		local sidx=0 wroot
		while IFS= read -r wroot; do
			[ -n "$wroot" ] && [ -d "$wroot" ] || continue
			case $wroot in /proc*|/sys*|/dev*) continue ;; esac
			sidx=$((sidx + 1))
			[ "$sidx" -gt 20 ] && break
			printf 's%s\t%s\n' "$sidx" "$wroot" >> "$SITES_FILE"
			scan_multipart_site "$wroot" "$MP_DIR/s$sidx.tsv" "$MP_DIR/s$sidx.ep.tsv" >/dev/null 2>&1
		done < "$TMPD/webroots.dedup.txt"
	fi

	# ---- 汇总 ----
	local n_aff=0 n_pat=0 n_unk=0 worst=0 v modphp_any=0
	if [ -s "$RECS/index" ]; then
		while IFS= read -r rd; do
			v=$(cat "$rd/verdict")
			case $v in
				affected) n_aff=$((n_aff + 1)) ;;
				patched)  n_pat=$((n_pat + 1)) ;;
				*)        n_unk=$((n_unk + 1)) ;;
			esac
			[ "$(cat "$rd/modphp")" = 1 ] && modphp_any=1
		done < "$RECS/index"
	fi

	# docker 容器里的 PHP 参与判定（以前只列出、不参与 → --docker-only 会误报不中）
	local n_docker=0 d_aff=0 d_pat=0 d_unk=0
	: > "$TMPD/docker-verdict.tsv"
	if [ -s "$TMPD/docker.tsv" ]; then
		local cid dimg dblob dver dmarker dres dv dr dmp
		while IFS=$'\t' read -r cid dimg dblob; do
			[ -z "$cid" ] && continue
			n_docker=$((n_docker + 1))
			dver=$(docker_row_get "$dblob" VER)
			dmarker=$(docker_row_get "$dblob" MARKER)
			dmp=$(docker_row_get "$dblob" MODPHP)
			[ "$dmp" = 1 ] && modphp_any=1
			IFS=$'\t' read -r dv dr <<EOF
$(docker_verdict "$dver" "$dmarker")
EOF
			case $dv in
				affected) d_aff=$((d_aff + 1)) ;;
				patched)  d_pat=$((d_pat + 1)) ;;
				*)        d_unk=$((d_unk + 1)) ;;
			esac
			printf '%s\t%s\t%s\t%s\t%s\n' "$cid" "$dimg" "$dv" "$dr" "$dver" >> "$TMPD/docker-verdict.tsv"
		done < "$TMPD/docker.tsv"
	fi

	local n_total=$((n_aff + n_pat + n_unk))
	local all_total=$((n_total + n_docker))
	local d_setup_failed=0
	[ "$DO_DOCKER" = 1 ] && [ "$n_docker" = 0 ] && d_setup_failed=1

	# 按 tier 汇总，不按 affected/patched 二元。
	# 取最坏的一档：red > orange > unknown > yellow
	local n_red=0 n_orange=0 n_yellow=0 n_tierunk=0 t
	if [ -s "$RECS/index" ]; then
		while IFS= read -r rd; do
			t=$(cat "$rd/tier" 2>/dev/null)
			case $t in
				red)     n_red=$((n_red + 1)) ;;
				orange)  n_orange=$((n_orange + 1)) ;;
				yellow)  n_yellow=$((n_yellow + 1)) ;;
				*)       n_tierunk=$((n_tierunk + 1)) ;;
			esac
		done < "$RECS/index"
	fi

	if [ "$n_red" -gt 0 ] || [ "$d_aff" -gt 0 ]; then worst=1
	elif [ "$n_orange" -gt 0 ]; then worst=0
	elif [ "$n_tierunk" -gt 0 ] || [ "$n_unk" -gt 0 ] || [ "$d_unk" -gt 0 ]; then worst=2
	elif [ "$all_total" -eq 0 ]; then worst=2   # 一个 PHP 都没找到 → 判不了，不是不中
	else worst=0; fi

	# 「已修但有残留」在退出码上仍是 0（版本没问题），但绝不能报成「不中」。
	local has_residual=0
	[ "$n_orange" -gt 0 ] && has_residual=1

	# docker 找不到时额外提示（不单独抬升退出码，但这个事实必须写出来）
	# 用户显式关掉 docker、又什么都没找到、也没指定 --root：
	# 这时「干净」这个结论最不可信 —— PHP 很可能就在容器里。
	if [ "$DO_DOCKER" = 0 ] && [ "$all_total" -eq 0 ] && [ -z "$EXTRA_ROOTS" ]; then
		warn '本次用 --no-docker 跳过了容器检查，且宿主机没找到 PHP；PHP 很可能跑在容器里。建议去掉 --no-docker 或加 --root 再跑一次 —— 不要据此认为这台机器干净'
	fi

	if [ "$d_setup_failed" = 1 ]; then
		if [ "$DOCKER_ONLY" = 1 ]; then
			warn '--docker-only 但没有扫到任何容器里的 PHP；退出码按 unknown 处理'
		else
			warn 'docker 不可用或没有运行中的容器；容器内的 PHP 没被检查到'
		fi
	fi

	# 受影响的分支里有没有「官方已经不发补丁」的（5.4-8.1 EOL）
	local eol_hit=0 eol_list=''
	if [ -s "$RECS/index" ]; then
		while IFS= read -r rd; do
			[ "$(cat "$rd/verdict")" = 'affected' ] || continue
			local b
			b=$(cat "$rd/version")
			b=${b%.*}
			if is_eol_branch "$(cat "$rd/version")"; then
				eol_hit=1
				case " $eol_list " in *" $b "*) ;; *) eol_list="$eol_list $b" ;; esac
			fi
		done < "$RECS/index"
	fi

	local verdict top_action label_zh chain_free=0
	# Chain A 的正确表述，任何一档都要带上，不许省。
	local chain_a='补丁修的是 OOM 和残留状态；upload_progress 的文件名写入是设计如此，配任何应用层 LFI 链子就通，责任在应用层。'

	if [ "$worst" = 1 ]; then
		verdict='affected'; label_zh='未修'
		if [ "$eol_hit" = 1 ]; then
			top_action="受影响的分支里有已 EOL 的（${eol_list# }）：官方不发补丁，社区 backport 也不保证。必须升到 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 之一。${chain_a}"
		else
			top_action="把 PHP 升到 8.5.12（或同分支 8.2.35 / 8.3.36 / 8.4.27）。${chain_a}"
		fi
	elif [ "$has_residual" = 1 ]; then
		# 版本够了，但链子还通或缓解没到位。这是最容易被误当成「安全」的一档。
		verdict='patched_with_residual'; label_zh='已修但有残留'
		# 找出最具体的那条原因（取第一条 orange）
		local rdt rreason
		if [ -s "$RECS/index" ]; then
			while IFS= read -r rdt; do
				[ "$(cat "$rdt/tier" 2>/dev/null)" = 'orange' ] || continue
				rreason=$(cat "$rdt/tier_reason" 2>/dev/null)
				break
			done < "$RECS/index"
		fi
		top_action="${rreason:-版本已修，但仍有残留风险}。${chain_a}"
	elif [ "$worst" = 2 ] && [ "$all_total" -eq 0 ]; then
		verdict='not_applicable'; label_zh='未发现 PHP'
		top_action='本机未找到任何 PHP 安装。如果 PHP 跑在容器 / 另一台机器 / 非标准路径，请加 --root 或 --docker-only，或直接对那台机器跑。不要因为“没找到”就当安全。'
	elif [ "$worst" = 2 ]; then
		verdict='unknown'; label_zh='判不了'
		top_action='先看清楚下面 unknown 的原因（版本无法解析 / 二进制被 strip / patch_composition 读不到），再用包管理器版本和发行版安全公告人工确认；不要当成安全。'
	else
		verdict='patched_mitigated'; label_zh='已修且缓解到位'
		top_action="版本在修复线以上、站点无 LFI 落点、PR#22113 等价修复在、缓解到位。${chain_a}"
	fi

	# ---- 输出 ----
	if [ "$OUT_JSON" = 1 ]; then
		json_out "$verdict" "$label_zh" "$top_action" "$n_aff" "$n_pat" "$n_unk" "$modphp_any" \
		         "$hostname" "$os" "$kernel" "$now" "$n_docker"
		exit "$worst"
	fi

	printf '%s\n' "$label_zh"
	printf '%s\n' "$top_action"
	printf '\n'
	printf '%s\n' '----------------------------------------------------------------'
	printf '%s v%s   CVE-2026-109618 / CVE-2026-109619 (CVSS 9.2)\n' "$TOOL_NAME" "$TOOL_VERSION"
	printf '主机 %s · %s %s · %s\n' "$hostname" "$os" "$kernel" "$now"
	printf '%s\n' '----------------------------------------------------------------'
	# 按三档报，不按 affected/patched —— 后者会让人以为「已修」就是安全。
	printf 'PHP 安装数 : %s   未修 %s / 已修但有残留 %s / 已修且缓解到位 %s' \
		"$n_total" "$n_red" "$n_orange" "$n_yellow"
	if [ "$n_tierunk" -gt 0 ]; then printf ' / 判不了 %s' "$n_tierunk"; fi
	printf '\n'
	printf 'mod_php    : %s\n' "$([ "$modphp_any" = 1 ] && printf '有（Chain D，无需应用代码即可触发）' || printf '未发现')"
	if [ "$n_docker" -gt 0 ]; then
		printf 'docker     : %s 个运行中容器含 PHP（受影响 %s / 已修 %s / 判不了 %s）\n' \
			"$n_docker" "$d_aff" "$d_pat" "$d_unk"
	elif [ "$DO_DOCKER" = 1 ]; then
		printf 'docker     : 没扫到容器里的 PHP\n'
	fi

	i=0
	if [ -s "$RECS/index" ]; then
		while IFS= read -r rd; do
			i=$((i + 1))
			render_text_install "$rd" "$i" "$n_total"
		done < "$RECS/index"
	fi

	# docker 容器段
	if [ -s "$TMPD/docker-verdict.tsv" ]; then
		printf '\n--- docker 容器 ---\n'
		local dcid dimg2 dv2 dr2 dver2 dblob2
		while IFS=$'\t' read -r dcid dimg2 dv2 dr2 dver2; do
			[ -z "$dcid" ] && continue
			case $dv2 in
				affected) printf '  [中]     %s  (%s)  PHP %s  · %s\n' "$dcid" "$dimg2" "$dver2" "$dr2" ;;
				patched)  printf '  [不中]   %s  (%s)  PHP %s  · %s\n' "$dcid" "$dimg2" "$dver2" "$dr2" ;;
				*)        printf '  [判不了] %s  (%s)  PHP %s  · %s\n' "$dcid" "$dimg2" "${dver2:-(未知)}" "$dr2" ;;
			esac
			dblob2=$(awk -F'\t' -v c="$dcid" '$1==c {print $3; exit}' "$TMPD/docker.tsv" 2>/dev/null)
			[ -n "$dblob2" ] && printf '%s' "$dblob2" | tr '|' '\n' \
				| sed -n 's/^\(SAPI\|MODPHP\)=/          \1=/p'
		done < "$TMPD/docker-verdict.tsv"
	fi

	render_overrides

	# 三档处置代价（在「说明」之前，因为它是结论的一部分）
	render_mitigation_all

	printf '\n--- 说明 ---\n'
	printf '  · 本工具只读：不写配置、不改文件、不发外部请求。\n'
	printf '  · "不中" 只代表版本/backport 层面已修，不代表应用没有 LFI（Chain A 在已修补版本上仍可用）。\n'
	printf '  · 缓解措施（关 upload_progress、关 backtraces）只能降风险，唯一完整修复是升级。\n'
	if [ -n "$WARNINGS" ]; then
		printf '  · 警告:\n'
		printf '%s' "$WARNINGS" | while IFS= read -r w; do [ -n "$w" ] && printf '      %s\n' "$w"; done
	fi

	exit "$worst"
}

json_out() {
	local verdict=$1 label=$2 action=$3 n_aff=$4 n_pat=$5 n_unk=$6 modphp=$7
	local hostname=$8 os=$9 kernel=${10} now=${11} n_docker=${12}
	local first=1 rd

	printf '{'
	printf '"schema_version":%s,' "$(jstr "$SCHEMA_VERSION")"
	printf '"tool":{"name":%s,"component":%s,"version":%s},' \
		"$(jstr "$TOOL_NAME")" "$(jstr "$TOOL_COMPONENT")" "$(jstr "$TOOL_VERSION")"
	printf '"generated_at":%s,' "$(jstr "$now")"
	printf '"host":{"hostname":%s,"os":%s,"kernel":%s},' "$(jstr "$hostname")" "$(jstr "$os")" "$(jstr "$kernel")"
	printf '"advisory":{"cve_ids":["CVE-2026-109618","CVE-2026-109619"],"cvss":"9.2",'
	printf '"affected_range":{"min":%s,"max":%s},' "$(jstr "$ADV_MIN")" "$(jstr "$ADV_MAX")"
	printf '"fixed_versions":{"8.2":%s,"8.3":%s,"8.4":%s,"8.5":%s},' \
		"$(jstr "$FIX_82")" "$(jstr "$FIX_83")" "$(jstr "$FIX_84")" "$(jstr "$FIX_85")"
	printf '"eol_branches_without_official_fix":["5.4","5.5","5.6","7.0","7.1","7.2","7.3","7.4","8.0","8.1"]},'
	printf '"verdict":%s,"verdict_label_zh":%s,"action":%s,' \
		"$(jstr "$verdict")" "$(jstr "$label")" "$(jstr "$action")"
	printf '"exit_code":%s,' "$([ "$verdict" = affected ] && echo 1 || { { [ "$verdict" = unknown ] || [ "$verdict" = not_applicable ]; } && echo 2 || echo 0; })"
	# targets_found 放在顶层：调用方不用去数 installs 数组就能判「这次到底查到东西没有」。
	# 与 total_targets 的区别：total_targets 是「参与判定的目标数」，targets_found 是
	# 「实际找到的 PHP 目标数」，两者在 --docker-only 漏配时可能不同。
	printf '"targets_found":%s,' "${all_total:-0}"
	printf '"summary":{"install_count":%s,"affected":%s,"patched":%s,"unknown":%s,"mod_php_present":%s,"docker_containers_with_php":%s,"docker_affected":%s,"docker_patched":%s,"docker_unknown":%s,"total_targets":%s},' \
		"$((n_aff + n_pat + n_unk))" "$n_aff" "$n_pat" "$n_unk" \
		"$([ "$modphp" = 1 ] && echo true || echo false)" "$n_docker" \
		"${d_aff:-0}" "${d_pat:-0}" "${d_unk:-0}" "${all_total:-0}"

	printf '"installs":['
	if [ -s "$RECS/index" ]; then
		while IFS= read -r rd; do
			[ "$first" = 1 ] || printf ','
			first=0
			json_install "$rd"
		done < "$RECS/index"
	fi
	printf '],'
	printf '"overrides":{"scanned":%s,"files":[' "$([ "$SCAN_WEBROOTS" = 1 ] && echo true || echo false)"
	first=1
	if [ "$SCAN_WEBROOTS" = 1 ] && [ -s "$OVR_FILE" ]; then
		while IFS=$'\t' read -r f ln line; do
			[ "$first" = 1 ] || printf ','
			first=0
			printf '{"file":%s,"line":%s,"directive":%s,"effect":%s}' \
				"$(jstr "$f")" "$ln" "$(jstr "$(printf '%s' "$line" | sed 's/^[[:space:]]*//')")" \
				"$(jstr "$(override_effect "$line")")"
		done < "$OVR_FILE"
	fi
	printf ']},'

	printf '"docker":['
	first=1
	if [ -s "$TMPD/docker-verdict.tsv" ]; then
		local dcid dimg3 dv3 dr3 dver3 dblob3
		while IFS=$'\t' read -r dcid dimg3 dv3 dr3 dver3; do
			[ -z "$dcid" ] && continue
			[ "$first" = 1 ] || printf ','
			first=0
			printf '{"id":%s,"image":%s,"version":%s,"verdict":%s,"verdict_reason":%s,"facts":{' \
				"$(jstr "$dcid")" "$(jstr "$dimg3")" "$(jstr "$dver3")" "$(jstr "$dv3")" "$(jstr "$dr3")"
			dblob3=$(awk -F'\t' -v c="$dcid" '$1==c {print $3; exit}' "$TMPD/docker.tsv" 2>/dev/null)
			local f1=1 line key v
			while IFS= read -r line; do
				[ -z "$line" ] && continue
				case $line in *=*) ;; *) continue ;; esac
				key=${line%%=*}
				v=${line#*=}
				case $key in
					BIN|VER|SAPI|BUILD|INI_FILE|SCAN_DIR|FPM|CGI|MODPHP|MARKER) ;;
					INI.*) key="ini.${key#INI.}" ;;
					*) continue ;;
				esac
				[ "$f1" = 1 ] || printf ','
				f1=0
				printf '%s:%s' "$(jstr "$key")" "$(jstr "$v")"
			done <<EOF2
$(printf '%s' "$dblob3" | tr '|' '\n')
EOF2
			printf '}}'
		done < "$TMPD/docker-verdict.tsv"
	fi
	printf '],'

	# 三档处置代价（mitigation_impact）
	if [ "$MITIGATIONS" = 1 ] && [ "$SCAN_WEBROOTS" = 1 ]; then
		mitigation_json
		printf ','
	else
		printf '"mitigation_impact":[],'
	fi

	printf '"warnings":['
	first=1
	if [ -n "$WARNINGS" ]; then
		while IFS= read -r w; do
			[ -z "$w" ] && continue
			[ "$first" = 1 ] || printf ','
			first=0
			printf '%s' "$(jstr "$w")"
		done <<EOF3
$WARNINGS
EOF3
	fi
	printf ']'
	printf '}\n'
}

# 作为库被 source 时不跑 main（单测用）；正常执行或 bash -s 管道时跑。
# 注意：bash -s < audit.sh 时 BASH_SOURCE 没有定义，set -u 下直接取会炸。
_pea_src=${BASH_SOURCE[0]:-}
if [ -z "$_pea_src" ] || [ "$_pea_src" = "$0" ]; then
	main "$@"
fi