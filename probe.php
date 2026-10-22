<?php
/**
 * probe.php — PHP 暴露面自查 (CVE-2026-109618 / CVE-2026-109619)
 * version 0.1.0
 *
 * 单文件、无依赖、无外部请求。放进 webroot，通过 HTTP 访问。
 *
 * 鉴权（三选一，按优先级）：
 *   1. 环境变量 PHP_EXPOSURE_AUDIT_TOKEN
 *   2. 环境变量 PHP_EXPOSURE_AUDIT_TOKEN_FILE 指向的文件
 *   3. 同目录下 .audit-token 文件（推荐，配合 web 服务器 deny 规则）
 * 令牌通过 header 传：Authorization: Bearer <token>
 *                或  X-Audit-Token: <token>
 *                或  ?token=<token>（会进访问日志，仅调试用）
 *
 * 无令牌 / 令牌错 → 404，内容与普通 404 无法区分。
 *
 * 输出：?format=json（默认）或 ?format=html
 * 兼容 PHP 5.4+（受影响区间下界就是 5.4.0，工具本身得能在上面跑）。
 */

// ---------------------------------------------------------------- 常量 ----
define('PEA_VERSION', '0.1.0');
define('PEA_SCHEMA_VERSION', '1.0');
define('PEA_ADV_MIN', '5.4.0');
define('PEA_ADV_MAX', '8.5.11');

$PEA_FIXED = array('8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12');
$PEA_MARKER_SYM = 'php_basic_early_rinit';
$PEA_MARKER_SYM2 = 'zend_handle_delayed_oom';
$PEA_CONTROL_SYM = 'php_request_shutdown';
$PEA_EOL_BRANCHES = array('5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1');

$PEA_KEYS = array(
	'session.upload_progress.enabled',
	'session.upload_progress.cleanup',
	'post_max_size',
	'upload_max_filesize',
	'memory_limit',
	'fatal_error_backtraces',
	'session.use_only_cookies',
	'session.serialize_handler',
	'opcache.enable',
);

// ---------------------------------------------------------------- 工具 ----

function pea_out_404()
{
	// 和 PHP 自带 404 一样的信息量：不说这里存在东西。
	if (!headers_sent()) {
		header('HTTP/1.1 404 Not Found', true, 404);
		header('Content-Type: text/html; charset=utf-8');
		header('X-Robots-Tag: noindex, nofollow');
	}
	echo "<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head><body>\n";
	echo "<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n";
	echo "</body></html>\n";
	exit;
}

function pea_token()
{
	$t = getenv('PHP_EXPOSURE_AUDIT_TOKEN');
	if (is_string($t) && $t !== '') {
		return $t;
	}
	$f = getenv('PHP_EXPOSURE_AUDIT_TOKEN_FILE');
	if (is_string($f) && $f !== '' && is_readable($f)) {
		$v = trim((string)@file_get_contents($f));
		if ($v !== '') {
			return $v;
		}
	}
	$local = dirname(__FILE__) . '/.audit-token';
	if (is_readable($local)) {
		$v = trim((string)@file_get_contents($local));
		if ($v !== '') {
			return $v;
		}
	}
	return null;
}

function pea_given_token()
{
	$auth = null;
	if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
		$auth = $_SERVER['HTTP_AUTHORIZATION'];
	} elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
		$auth = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
	} elseif (function_exists('getallheaders')) {
		// Apache + mod_php 默认会把 Authorization 从 $_SERVER 里删掉
		// （没有 CGIPassAuth On 时），只能从这里捞。
		$hdrs = getallheaders();
		if (is_array($hdrs)) {
			foreach ($hdrs as $k => $v) {
				if (strcasecmp($k, 'Authorization') === 0) {
					$auth = $v;
					break;
				}
			}
		}
	}
	if (is_string($auth) && stripos($auth, 'Bearer ') === 0) {
		return substr($auth, 7);
	}
	if (isset($_SERVER['HTTP_X_AUDIT_TOKEN'])) {
		return $_SERVER['HTTP_X_AUDIT_TOKEN'];
	}
	if (isset($_GET['token'])) {
		return $_GET['token'];
	}
	return null;
}

function pea_ct_eq($a, $b)
{
	if (function_exists('hash_equals')) {
		return hash_equals($a, $b);
	}
	if (!is_string($a) || !is_string($b) || strlen($a) !== strlen($b)) {
		return false;
	}
	$r = 0;
	for ($i = 0; $i < strlen($a); $i++) {
		$r |= ord($a[$i]) ^ ord($b[$i]);
	}
	return $r === 0;
}

function pea_ver_num($v)
{
	$v = preg_replace('/[-+~].*$/', '', $v);
	$p = explode('.', $v);
	$a = isset($p[0]) && ctype_digit($p[0]) ? (int)$p[0] : 0;
	$b = isset($p[1]) && ctype_digit($p[1]) ? (int)$p[1] : 0;
	$c = isset($p[2]) && ctype_digit($p[2]) ? (int)$p[2] : 0;
	return $a * 1000000 + $b * 1000 + $c;
}

/**
 * 版本串能不能解析成一个真实的 PHP 版本。
 *
 * pea_ver_num('') / pea_ver_num('custom') 都会返回 0，
 * 而 0 < PEA_ADV_MIN 会让判定落到 below_affected_range → patched。
 * 也就是说：探不到版本 → 报「不中」→ exit 0。这是假阴性，必须先挡住。
 */
function pea_version_parseable($v)
{
	if (!is_string($v) && !is_numeric($v)) {
		return false;
	}
	$v = trim((string)$v);
	// 必须是以「数字.数字」开头的三段式（允许 8.5 / 8.5.12 / 8.5.12-1ubuntu1）
	return (bool)preg_match('/^\d+\.\d+/', $v);
}

function pea_vcmp($x, $y)
{
	$n = pea_ver_num($x) - pea_ver_num($y);
	return $n < 0 ? -1 : ($n > 0 ? 1 : 0);
}

function pea_to_bytes($v)
{
	$v = strtoupper(trim((string)$v));
	if ($v === '' || $v === '0') {
		return 0;
	}
	if ($v === '-1') {
		return -1;
	}
	$unit = substr($v, -1);
	$num = $v;
	if ($unit === 'K' || $unit === 'M' || $unit === 'G') {
		$num = substr($v, 0, -1);
	} else {
		$unit = '';
	}
	if (!ctype_digit($num)) {
		return -1;
	}
	$n = (int)$num;
	if ($unit === 'K') {
		return $n * 1024;
	}
	if ($unit === 'M') {
		return $n * 1024 * 1024;
	}
	if ($unit === 'G') {
		return $n * 1024 * 1024 * 1024;
	}
	return $n;
}

/**
 * 从 /proc/self/maps 找当前进程加载的 PHP 二进制/共享对象。
 * 返回候选文件路径数组（可能为空）。
 */
function pea_self_artifacts()
{
	$out = array();
	if (PHP_BINARY !== '' && is_readable(PHP_BINARY)) {
		$out[] = PHP_BINARY;
	}
	if (is_readable('/proc/self/exe')) {
		$real = @readlink('/proc/self/exe');
		if ($real && is_readable($real)) {
			$out[] = $real;
		}
	}
	if (is_readable('/proc/self/maps')) {
		$maps = @file('/proc/self/maps', FILE_IGNORE_NEW_LINES);
		if (is_array($maps)) {
			foreach ($maps as $line) {
				if (!preg_match('#\s(\S*libphp[0-9]*\.so\S*)$#', $line, $m)) {
					continue;
				}
				if (is_readable($m[1])) {
					$out[] = $m[1];
				}
			}
		}
	}
	// 常见 mod_php 位置（open_basedir 会挡住，挡了就自然失败）
	$guess = array(
		'/usr/lib/apache2/modules/libphp.so',
		'/usr/lib64/httpd/modules/libphp.so',
		'/usr/lib/httpd/modules/libphp.so',
		'/usr/local/apache/modules/libphp.so',
		'/usr/local/apache2/modules/libphp.so',
	);
	foreach ($guess as $g) {
		if (is_readable($g)) {
			$out[] = $g;
		}
	}
	return array_values(array_unique($out));
}

/**
 * 在二进制里找 patch 标记。
 * 返回 array(state, evidence[]) —— state: present | absent_conclusive | inconclusive
 */
function pea_backport_marker()
{
	global $PEA_MARKER_SYM, $PEA_MARKER_SYM2, $PEA_CONTROL_SYM;

	$files = pea_self_artifacts();
	$evidence = array();
	$sawControl = false;
	$sawMarker = false;
	$readable = 0;

	foreach ($files as $f) {
		$fh = @fopen($f, 'rb');
		if (!$fh) {
			$evidence[] = 'unreadable:' . $f;
			continue;
		}
		$readable++;
		$marker = false;
		$control = false;
		$buf = '';
		$overlap = 64;
		while (!feof($fh)) {
			$chunk = fread($fh, 1048576);
			if ($chunk === false || $chunk === '') {
				break;
			}
			$hay = $buf . $chunk;
			if (!$marker && (strpos($hay, $PEA_MARKER_SYM) !== false || strpos($hay, $PEA_MARKER_SYM2) !== false)) {
				$marker = true;
			}
			if (!$control && strpos($hay, $PEA_CONTROL_SYM) !== false) {
				$control = true;
			}
			if ($marker && $control) {
				break;
			}
			$buf = substr($hay, -$overlap);
		}
		fclose($fh);

		if ($control) {
			$sawControl = true;
		}
		if ($marker) {
			$sawMarker = true;
		}
		$evidence[] = ($marker ? 'marker' : ($control ? 'no-marker' : 'stripped')) . ':' . $f;
	}

	if ($sawMarker) {
		return array('present', $evidence);
	}
	if ($sawControl) {
		return array('absent_conclusive', $evidence);
	}
	if ($readable === 0) {
		return array('inconclusive', $evidence);
	}
	return array('inconclusive', $evidence);
}

function pea_ini_report($keys)
{
	$all = ini_get_all(null, true);
	$out = array();
	foreach ($keys as $k) {
		$e = isset($all[$k]) ? $all[$k] : null;
		$local = $e === null ? null : $e['local_value'];
		$global = $e === null ? null : $e['global_value'];
		$out[$k] = array(
			'value' => $local === null ? null : (string)$local,
			'global_value' => $global === null ? null : (string)$global,
			'local_value' => $local === null ? null : (string)$local,
			'access' => $e === null ? null : (int)$e['access'],
			'overridden' => ($local !== $global),
			'state' => pea_ini_state($k, $local === null ? '' : (string)$local),
			'advice' => pea_ini_advice($k),
		);
	}
	return $out;
}

function pea_ini_state($k, $v)
{
	$lv = strtolower(trim($v));
	if ($k === 'session.upload_progress.enabled' || $k === 'fatal_error_backtraces') {
		if ($lv === '' || $lv === '0' || $lv === 'off' || $lv === 'false' || $lv === 'no') {
			return 'ok';
		}
		return 'weak';
	}
	if ($k === 'memory_limit') {
		if ($lv === '-1') {
			return 'ok';
		}
		$b = pea_to_bytes($v);
		if ($b > 0 && $b <= 134217728) {
			return 'info';
		}
		return 'ok';
	}
	return 'info';
}

function pea_ini_advice($k)
{
	if ($k === 'session.upload_progress.enabled') {
		return '0';
	}
	if ($k === 'fatal_error_backtraces') {
		return '0';
	}
	return null;
}

/**
 * 找 .user.ini / .htaccess 覆盖链。
 *
 * 分两类报：
 *   applies_to_me = true  → 当前脚本所在的目录���及其祖先，这些指令真的作用在本进程上
 *   applies_to_me = false → 文档根下的其他目录（限深度），不影响本进程，但说明全站有覆盖
 *
 * 表面上看第二类跟 probe 自己无关，但判断“这台机器上缓解措施能不能立住”必须知道它。
 */
function pea_override_files()
{
	$targets = array(); // 'dir|applies'
	$cur = dirname(__FILE__);
	$docroot = isset($_SERVER['DOCUMENT_ROOT']) ? realpath($_SERVER['DOCUMENT_ROOT']) : false;
	$inDocroot = false;

	if ($docroot) {
		$prefix = rtrim($docroot, '/') . '/';
		if ($cur === rtrim($docroot, '/') || strpos($cur . '/', $prefix) === 0) {
			$inDocroot = true;
			$rel = trim(substr($cur . '/', strlen($prefix)), '/');
			$acc = rtrim($docroot, '/');
			$chain = array($acc);
			if ($rel !== '') {
				foreach (explode('/', $rel) as $seg) {
					if ($seg === '') {
						continue;
					}
					$acc .= '/' . $seg;
					$chain[] = $acc;
				}
			}
			// 祖先（含自己）→ 作用在本进程上，按从根到叶的顺序
			foreach ($chain as $d) {
				$targets[] = array($d, true);
			}
		} else {
			$targets[] = array($cur, true);
			$targets[] = array($docroot, false);
		}
	} else {
		$targets[] = array($cur, true);
	}

	// 文档根下的旁路目录：最多 2 层，只查这两个文件名
	if ($inDocroot) {
		$root = rtrim($docroot, '/');
		$skip = array('node_modules', 'vendor', '.git', 'cache', 'tmp');
		$queue = array(array($root, 0));
		$seen = 0;
		while ($queue && $seen < 400) {
			list($d, $depth) = array_shift($queue);
			$seen++;
			$entries = @scandir($d);
			if (!is_array($entries)) {
				continue;
			}
			foreach ($entries as $e) {
				if ($e === '.' || $e === '..' || in_array($e, $skip, true)) {
					continue;
				}
				$p = $d . '/' . $e;
				if (!is_dir($p) || is_link($p)) {
					continue;
				}
				if ($depth < 2) {
					$queue[] = array($p, $depth + 1);
				}
				if ($p !== $cur) {
					$targets[] = array($p, false);
				}
			}
		}
	}

	$allowed = array(
		'session.upload_progress.enabled', 'session.upload_progress.cleanup',
		'post_max_size', 'upload_max_filesize', 'memory_limit',
		'fatal_error_backtraces', 'session.use_only_cookies',
		'session.serialize_handler', 'opcache.enable',
	);

	$found = array();
	$done = array();
	foreach ($targets as $t) {
		list($d, $applies) = $t;
		foreach (array('.user.ini', '.htaccess', 'php.ini') as $name) {
			$p = $d . '/' . $name;
			if (isset($done[$p])) {
				continue;
			}
			$done[$p] = true;
			if (!is_file($p) || !is_readable($p)) {
				continue;
			}
			$lines = @file($p, FILE_IGNORE_NEW_LINES);
			if (!is_array($lines)) {
				continue;
			}
			$hits = array();
			foreach ($lines as $i => $line) {
				$s = trim($line);
				if ($s === '' || $s[0] === ';' || $s[0] === '#') {
					continue;
				}
				if (preg_match('/^\s*(php_value|php_flag|php_admin_value|php_admin_flag)\s+(\S+)\s*(.*)$/i', $s, $m)) {
					$key = $m[2];
					$val = trim($m[3]);
				} elseif (preg_match('/^\s*([A-Za-z0-9_.]+)\s*=\s*(.*)$/', $s, $m)) {
					$key = $m[1];
					$val = trim($m[2]);
				} else {
					continue;
				}
				if (!in_array($key, $allowed, true)) {
					continue;
				}
				$hits[] = array(
					'file' => $p,
					'line' => $i + 1,
					'key' => $key,
					'value' => $val,
					'effect' => pea_override_effect($key, $val),
				);
			}
			if ($hits) {
				$found[] = array('file' => $p, 'applies_to_me' => $applies, 'directives' => $hits);
			}
		}
	}

	// 作用在自己身上的排前面
	usort($found, array('PeaOverrideSorter', 'cmp'));
	return $found;
}

class PeaOverrideSorter
{
	public static function cmp($a, $b)
	{
		$x = $a['applies_to_me'] ? 0 : 1;
		$y = $b['applies_to_me'] ? 0 : 1;
		if ($x !== $y) {
			return $x < $y ? -1 : 1;
		}
		return strcmp($a['file'], $b['file']);
	}
}

function pea_override_effect($key, $val)
{
	$lv = strtolower(trim($val));
	$off = ($lv === '0' || $lv === 'off' || $lv === 'false' || $lv === 'no' || $lv === '');
	if ($key === 'session.upload_progress.enabled' || $key === 'fatal_error_backtraces') {
		return $off ? 'ok' : 'weakens';
	}
	if ($key === 'post_max_size' || $key === 'upload_max_filesize' || $key === 'memory_limit') {
		return 'raises';
	}
	return 'neutral';
}

function pea_sapi_flags($sapi)
{
	$flags = array(
		'mod_php' => false,
		'fpm' => false,
		'cgi' => false,
		'cli' => false,
		'litespeed' => false,
		'frankenphp' => false,
	);
	if ($sapi === 'apache2handler') {
		$flags['mod_php'] = true;
	} elseif (strpos($sapi, 'fpm') !== false) {
		$flags['fpm'] = true;
	} elseif (strpos($sapi, 'cgi') !== false) {
		$flags['cgi'] = true;
	} elseif (strpos($sapi, 'litespeed') !== false) {
		$flags['litespeed'] = true;
	} elseif (strpos($sapi, 'frankenphp') !== false) {
		$flags['frankenphp'] = true;
	} elseif ($sapi === 'cli' || strpos($sapi, 'cli') === 0) {
		$flags['cli'] = true;
	}
	return $flags;
}

// ------------------------------------------------------------ mitigation ----
// 三档处置代价评估。
// probe 只能看到自己所在的 docroot，所以扫描是有界的；这一点必须写进输出，
// 不能让人以为它看到了全站。

define('PEA_MP_MAX_FILES', 1500);

define('PEA_MP_MAX_DEPTH', 5);

/** 按路径 + 行内容猜用途。猜不出返回空串，绝不编造。 */
function pea_guess_purpose($path, $hint)
{
	$low = strtolower($path . ' ' . $hint);
	$map = array(
		'wp-admin/async-upload' => 'WordPress 媒体库上传',
		'wp-admin/media-new' => 'WordPress 媒体库上传',
		'plupload' => 'WordPress 媒体库上传',
		'avatar' => '头像上传',
		'头像' => '头像上传',
		'product' => '商品图上传',
		'商品' => '商品图上传',
		'checkout' => '结账/购物车（可能带附件）',
		'cart' => '结账/购物车（可能带附件）',
		'resume' => '简历上传',
		'简历' => '简历上传',
		'gallery' => '相册/图片上传',
		'album' => '相册/图片上传',
		'相册' => '相册/图片上传',
		'logo' => 'Logo 上传',
		'attach' => '附件上传',
		'附件' => '附件上传',
		'import' => '数据导入（可能走 multipart）',
		'导入' => '数据导入（可能走 multipart）',
		'ticket' => '工单附件上传',
		'工单' => '工单附件上传',
		'kyc' => '证件/实名认证上传',
		'idcard' => '证件/实名认证上传',
		'证件' => '证件/实名认证上传',
		'invoice' => '发票上传',
		'发票' => '发票上传',
		'banner' => 'Banner 上传',
		'cover' => '封面图上传',
		'封面' => '封面图上传',
		'editor' => '富文本编辑器附件',
		'编辑器' => '富文本编辑器附件',
		'profile' => '个人资料表单（可能含头像）',
		'个人资料' => '个人资料表单（可能含头像）',
		'media' => '媒体文件上传',
		'媒体' => '媒体文件上传',
		'upload' => '上传接口',
		'上传' => '上传接口',
	);
	foreach ($map as $needle => $label) {
		if (strpos($low, $needle) !== false) {
			return $label;
		}
	}
	return '';
}

/**
 * 扫 docroot 里的 multipart 表单。只读，不发请求。
 * 返回 array('blocks'=>[], 'endpoints'=>[], 'scanned'=>int, 'truncated'=>bool, 'limited'=>string|null)
 */
function pea_scan_multipart($docroot)
{
	$out = array(
		'blocks' => array(),
		'endpoints' => array(),
		'scanned' => 0,
		'truncated' => false,
		'limited' => null,
	);
	if (!$docroot || !is_dir($docroot)) {
		$out['limited'] = 'DOCUMENT_ROOT 不可用或不可读，没法扫表单';
		return $out;
	}
	$root = rtrim(realpath($docroot), '/');
	if ($root === '' || !is_readable($root)) {
		$out['limited'] = 'DOCUMENT_ROOT 不可读（open_basedir / 权限）';
		return $out;
	}

	$ext = array('.php', '.html', '.htm', '.twig', '.tpl', '.jsp', '.asp', '.aspx', '.vue', '.jsx', '.tsx', '.js');
	$skip = array('node_modules', 'vendor', '.git', 'bower_components', 'cache', 'tmp');
	$queue = array(array($root, 0));
	$seen = 0;
	$files = 0;

	while ($queue) {
		list($dir, $depth) = array_shift($queue);
		$entries = @scandir($dir);
		if (!is_array($entries)) {
			continue;
		}
		foreach ($entries as $e) {
			if ($e === '.' || $e === '..') {
				continue;
			}
			$p = $dir . '/' . $e;
			if (is_dir($p)) {
				if (is_link($p) || in_array($e, $skip, true) || $depth >= PEA_MP_MAX_DEPTH) {
					continue;
				}
				$queue[] = array($p, $depth + 1);
				continue;
			}
			$seen++;
			if ($seen > PEA_MP_MAX_FILES * 4) {
				$out['truncated'] = true;
				break 2;
			}
			$lower = strtolower($e);
			$hitExt = false;
			foreach ($ext as $x) {
				if (substr($lower, -strlen($x)) === $x) {
					$hitExt = true;
					break;
				}
			}
			if (!$hitExt || !is_readable($p)) {
				continue;
			}
			// 不要把工具自己的源码当成上传表单。
			// probe.php 里含有 "multipart/form-data" 这个字符串（就是匹配规则本身），
			// 不排掉的话它会被自己报成一个「疑似上传」的文件。
			if ($p === __FILE__ || $e === 'probe.php' || $e === 'audit.sh') {
				continue;
			}
			$size = @filesize($p);
			if ($size !== false && $size > 524288) {
				continue;
			}
			$files++;
			if ($files > PEA_MP_MAX_FILES) {
				$out['truncated'] = true;
				break 2;
			}
			$lines = @file($p, FILE_IGNORE_NEW_LINES);
			if (!is_array($lines)) {
				continue;
			}
			$hasEnc = false;
			$hasFileInput = false;
			foreach ($lines as $ln => $line) {
				$l = strtolower($line);
				if (strpos($l, 'multipart/form-data') !== false) {
					$hasEnc = true;
				}
				if (preg_match('/<input[^>]*type\s*=\s*["\']?file/', $l)) {
					$hasFileInput = true;
				}
			}

			if ($hasEnc) {
				// 每个 enctype 行算一个表单；同一表单不再被 file input 重复计一次
				$n = 0;
				foreach ($lines as $ln => $line) {
					if (stripos($line, 'multipart/form-data') === false) {
						continue;
					}
					if ($n++ >= 6) {
						break;
					}
					$conf = $hasFileInput ? 'high' : 'medium';
					$purpose = pea_guess_purpose($p, $line);
					$out['blocks'][] = array(
						'file' => $p,
						'line' => $ln + 1,
						'kind' => 'form_multipart',
						'confidence' => $conf,
						'purpose' => $purpose === '' ? '疑似上传（路径和字段名都看不出用途）' : $purpose,
						'evidence' => substr(trim($line), 0, 160),
					);
				}
			} elseif ($hasFileInput || stripos(implode("\n", array_slice($lines, 0, 200)), 'new FormData(') !== false
				|| stripos(implode("\n", array_slice($lines, 0, 200)), 'async-upload.php') !== false) {
				$kind = 'input_file';
				$conf = 'medium';
				$probe = strtolower(implode("\n", array_slice($lines, 0, 200)));
				if (strpos($probe, 'async-upload.php') !== false || strpos($probe, 'media-new.php') !== false) {
					$kind = 'wp_media';
					$conf = 'high';
				} elseif (strpos($probe, 'new formdata(') !== false) {
					$kind = 'formdata_js';
					$conf = 'low';
				}
				$purpose = pea_guess_purpose($p, '');
				$out['blocks'][] = array(
					'file' => $p,
					'line' => 0,
					'kind' => $kind,
					'confidence' => $conf,
					'purpose' => $purpose === '' ? '疑似上传（路径和字段名都看不出用途）' : $purpose,
					'evidence' => 'file input / FormData / WordPress 上传入口（无 enctype）',
				);
			}
		}
	}

	if (!$out['blocks']) {
		$out['limited'] = 'docroot 里没找到 multipart 表单；纯 API / SPA 用 JS 动态拼请求时静态扫不到';
	}
	return $out;
}

/**
 * 三档处置代价。
 *
 * A 升级：当前版本 → 目标版本；EOL 分支（8.1 及更早）要说明官方已停支。
 * B 403 multipart：扫 docroot 列出会被打废的功能。
 * C 只关 upload_progress：写清只治 109619，对 109618 无效。
 */
function pea_mitigation($verdict, $phpVersion, $branch, $fix)
{
	$eol = array('5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1');
	$isEol = in_array($branch, $eol, true);

	// ---- A ----
	$target = $fix !== null ? $fix : '8.5.12';
	if ($isEol) {
		$aNote = '分支 ' . $branch . ' 官方已停支（EOL）：需发行版 backport 或 TuxCare ELS，否则升到 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 之一。';
		$aTarget = '8.2.35';
	} elseif ($verdict === 'patched') {
		$aNote = '已在这条分支的修复线以上，无需升级。';
		$aTarget = $target;
	} elseif ($verdict === 'unknown') {
		$aNote = '版本不在公告区间内，给不出目标版本。';
		$aTarget = null;
	} else {
		$aNote = '升级到同分支修复版；不改代码、不改配置。';
		$aTarget = $target;
	}

	$a = array(
		'id' => 'upgrade_php',
		'title' => '升级 PHP',
		'cost' => 'low',
		'from_version' => $phpVersion,
		'to_version' => $aTarget,
		'note' => $aNote,
		'blocks' => array(),
		'notes' => array('不改代码、不改配置', '唯一完整修复'),
	);

	// ---- B ----
	$docroot = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : null;
	$scan = pea_scan_multipart($docroot);
	$b = array(
		'id' => 'block_multipart',
		'title' => 'Web 层 403 multipart',
		'cost' => $scan['blocks'] ? 'high' : 'low',
		'blocks' => $scan['blocks'],
		'suspected_endpoints' => $scan['endpoints'],
		'scanned_files' => $scan['scanned'],
		'truncated' => $scan['truncated'],
		'limitation' => $scan['limited'],
		'notes' => array(
			'不发起任何请求，只读文件',
			'403 掉 multipart 会同时废掉商品图 / 结账等上传',
			'probe 只看得到自己的 docroot，其他 vhost 需用 audit.sh',
		),
	);

	// ---- C ----
	$covers = array('CVE-2026-109619 的 session 注入路径');
	$noCover = array('CVE-2026-109618（Zend 引擎 OOM，与 upload_progress 无关）');
	if (pea_vcmp($phpVersion, '8.5.0') >= 0) {
		$noCover[] = '8.5.x 的 fatal_error_backtraces 臂（需单独设 0）';
	}
	$c = array(
		'id' => 'disable_upload_progress',
		'title' => '只关 session.upload_progress',
		'cost' => 'low',
		'covers' => $covers,
		'does_not_cover' => $noCover,
		'blocks' => array(),
		'notes' => array(
			'不是完整修复',
			'任何超大 multipart POST 仍能触发 109618 的 OOM',
			'覆盖链里的 .htaccess / .user.ini 可能把它重新打开',
		),
	);

	return array(
		'site' => isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : null,
		'forms_found' => count($scan['blocks']),
		'endpoints_suspected' => count($scan['endpoints']),
		'options' => array($a, $b, $c),
	);
}

// ============================================================== axes ======
// 多轴判定。同一个引擎在 audit.sh 里有 bash 版本，两边必须给出一致的答案。
//
// 单看版本号会给出两种错误答案：
//   1. 版本够新 → 报「安全」，但 Chain A 的写原语是设计如此，压根没修
//   2. 版本够新 → 报「安全」，但 PR#22113（session fixation 守卫）从未合并

// 官方修复版里都不含 PR#22113（除非发行版单独 backport）
function pea_is_official_fix($ver)
{
	global $PEA_FIXED;
	foreach ($PEA_FIXED as $f) {
		if ($ver === $f) {
			return true;
		}
	}
	return false;
}

function pea_ini_on($v)
{
	$lv = strtolower(trim((string)$v));
	return !($lv === '' || $lv === '0' || $lv === 'off' || $lv === 'false' || $lv === 'no');
}

/**
 * 扫 docroot 里的 LFI 落点。只读，不发请求。
 *
 * 直接式：include $_GET['tpl'];
 * 间接式：$tpl = $_GET['tpl']; include $tpl;
 *
 * 间接式才是真实代码里最常见的样子。只抓直接式会把「链子还通」误报成
 * 「没找到落点」，而这个工具里漏报是最坏的错误。
 */
function pea_scan_lfi($docroot)
{
	$out = array('sinks' => array(), 'scanned' => 0, 'limited' => null, 'scanned_ok' => false);
	if (!$docroot || !is_dir($docroot)) {
		$out['limited'] = 'DOCUMENT_ROOT 不可用或不可读，没法扫 LFI 落点';
		return $out;
	}
	$root = rtrim(realpath($docroot), '/');
	if ($root === '' || !is_readable($root)) {
		$out['limited'] = 'DOCUMENT_ROOT 不可读（open_basedir / 权限）';
		return $out;
	}
	$out['scanned_ok'] = true;

	$skip = array('node_modules', 'vendor', '.git', 'bower_components', 'cache', 'tmp');
	$queue = array(array($root, 0));
	$files = 0;

	$reDirect = '/(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)|(file_get_contents|readfile|fopen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i';
	$reSink = '/(include|require)(_once)?\s*\(?\s*\$([A-Za-z_][A-Za-z0-9_]*)|(file_get_contents|readfile|fopen)\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)/i';

	while ($queue) {
		list($dir, $depth) = array_shift($queue);
		$entries = @scandir($dir);
		if (!is_array($entries)) {
			continue;
		}
		foreach ($entries as $e) {
			if ($e === '.' || $e === '..') {
				continue;
			}
			$p = $dir . '/' . $e;
			if (is_dir($p)) {
				if (is_link($p) || in_array($e, $skip, true) || $depth >= PEA_MP_MAX_DEPTH) {
					continue;
				}
				$queue[] = array($p, $depth + 1);
				continue;
			}
			if (strtolower(substr($e, -4)) !== '.php' || !is_readable($p)) {
				continue;
			}
			if (basename($p) === 'probe.php') {
				continue;
			}
			$size = @filesize($p);
			if ($size !== false && $size > 524288) {
				continue;
			}
			$files++;
			if ($files > PEA_MP_MAX_FILES) {
				break 2;
			}
			$lines = @file($p, FILE_IGNORE_NEW_LINES);
			if (!is_array($lines)) {
				continue;
			}
			$n = count($lines);
			for ($i = 0; $i < $n; $i++) {
				$line = $lines[$i];
				if (preg_match($reDirect, $line)) {
					$out['sinks'][] = array(
						'file' => $p,
						'line' => $i + 1,
						'kind' => 'direct',
						'evidence' => substr(trim($line), 0, 140),
					);
					continue;
				}
				if (!preg_match($reSink, $line, $m)) {
					continue;
				}
				$var = !empty($m[3]) ? $m[3] : (!empty($m[5]) ? $m[5] : '');
				if ($var === '') {
					continue;
				}
				// 这个变量在本文件里被超全局污染过吗
				$taintRe = '/\$' . preg_quote($var, '/') . '\s*=\s*[^=].*\$_(GET|POST|REQUEST|COOKIE|FILES)/i';
				for ($j = 0; $j < $n; $j++) {
					if ($j === $i) {
						continue;
					}
					if (preg_match($taintRe, $lines[$j])) {
						$out['sinks'][] = array(
							'file' => $p,
							'line' => $i + 1,
							'kind' => 'indirect($' . $var . ')',
							'evidence' => substr(trim($line), 0, 110)
								. ' <= ' . substr(trim($lines[$j]), 0, 80),
						);
						break;
					}
				}
			}
		}
	}

	$out['scanned'] = $files;
	if (!$out['sinks']) {
		$out['limited'] = 'docroot 里没找到；静态扫描证不了「不存在」（动态拼接、框架路由、层层转手的变量都扫不到）';
	}
	return $out;
}

/**
 * 算七轴 + tier。
 * $ctx = array(ver, branch, fix, verdict, markerState, ini, overrides, docroot)
 */
function pea_axes($ctx)
{
	$ver = $ctx['ver'];
	$verdict = $ctx['verdict'];
	$marker = $ctx['markerState'];
	$ini = $ctx['ini'];
	$overrides = $ctx['overrides'];
	$branch = $ctx['branch'];
	$sapi = $ctx['sapi'];

	$axes = array();

	// 1. version
	$axes['version'] = array(
		'state' => $verdict === 'patched'
			? (pea_vcmp($ver, PEA_ADV_MIN) < 0 ? 'below_affected' : 'patched')
			: ($verdict === 'affected' ? 'affected' : 'unknown'),
		'detail' => $ver,
	);

	// 2. patch_composition —— 有没有 PR#22113 等价修复
	if (pea_is_official_fix($ver)) {
		$axes['patch_composition'] = array(
			'state' => 'pr22113_absent',
			'detail' => $ver . ' 是上游修复版，PR#22113 未合并，源码里没有 session fixation 守卫',
		);
	} else {
		$axes['patch_composition'] = array(
			'state' => 'unknown',
			'detail' => 'probe 读不到包补丁列表（自编译/镜像/无包信息），判不了是否含 PR#22113 等价修复',
		);
	}

	// 3. upload_progress（开着 = 写原语在）
	$up = isset($ini['session.upload_progress.enabled']['value'])
		? $ini['session.upload_progress.enabled']['value'] : null;
	// PHP 把 Off 归一化成空串，直接拼出来会很怪，这里显式说明。
	$upShown = $up === null ? '(不可用)' : ($up === '' ? '(空 → 视为关闭)' : $up);
	$axes['upload_progress'] = array(
		'state' => ($up !== null && pea_ini_on($up)) ? 'enabled' : 'disabled',
		'detail' => 'session.upload_progress.enabled=' . $upShown,
	);

	// 4. lfi_exposure
	$lfi = pea_scan_lfi($ctx['docroot']);
	if ($lfi['sinks']) {
		$lfiState = 'sink_found';
		$lfiDetail = count($lfi['sinks']) . ' 处可疑 include/文件读取（静态扫描，需人工确认是否真可控）';
	} elseif (!$lfi['scanned_ok']) {
		// 扫都没扫成，不能算「没找到」——这两件事必须分开。
		$lfiState = 'not_scanned';
		$lfiDetail = $lfi['limited'];
	} else {
		$lfiState = 'no_sink_found';
		$lfiDetail = $lfi['limited'];
	}
	$axes['lfi_exposure'] = array(
		'state' => $lfiState,
		'detail' => $lfiDetail,
		'sinks' => $lfi['sinks'],
	);

	// 5. serializer_reset
	if (strpos($sapi, 'fpm') !== false) {
		if ($marker === 'present') {
			$axes['serializer_reset'] = array('state' => 'covered', 'detail' => 'FPM 跨请求残留状态已被补丁覆盖');
		} elseif ($marker === 'absent_conclusive') {
			$axes['serializer_reset'] = array('state' => 'leaks', 'detail' => 'FPM + 二进制确定无补丁：跨请求残留状态仍在');
		} else {
			$axes['serializer_reset'] = array('state' => 'unknown', 'detail' => 'FPM，但读不到二进制，判不了');
		}
	} else {
		$axes['serializer_reset'] = array('state' => 'not_applicable', 'detail' => '当前 SAPI 不是 FPM');
	}

	// 6. fatal_error_backtraces（仅 8.5.x）
	if (pea_vcmp($ver, '8.5.0') >= 0) {
		$bp = isset($ini['fatal_error_backtraces']['value']) ? $ini['fatal_error_backtraces']['value'] : null;
		if ($bp === null) {
			$axes['fatal_error_backtraces'] = array('state' => 'unknown', 'detail' => '读不到该指令');
		} else {
			$axes['fatal_error_backtraces'] = array(
				'state' => pea_ini_on($bp) ? 'on' : 'off',
				'detail' => 'fatal_error_backtraces=' . $bp . '（8.5.x 须为 0）',
			);
		}
	} else {
		$axes['fatal_error_backtraces'] = array('state' => 'not_applicable', 'detail' => '只有 8.5.x 有这个指令');
	}

	// 7. opcache
	$opc = isset($ini['opcache.enable']['value']) ? $ini['opcache.enable']['value'] : null;
	if ($opc === null || !pea_ini_on($opc)) {
		$axes['opcache'] = array('state' => 'off', 'detail' => 'OPcache 未启用');
	} elseif ($marker === 'present') {
		$axes['opcache'] = array('state' => 'covered', 'detail' => 'OPcache 开着，补丁标记在');
	} else {
		$axes['opcache'] = array('state' => 'needs_patch', 'detail' => 'OPcache 开着且补丁标记缺失，共享内存是一条关不掉的臂');
	}

	// ---- tier ----
	$weak = 0;
	foreach ($overrides as $o) {
		foreach ($o['directives'] as $d) {
			if ($d['effect'] === 'weakens') {
				$weak++;
			}
		}
	}

	$tier = 'unknown';
	$tierReason = '判定异常';

	if ($axes['version']['state'] === 'unknown') {
		$tier = 'unknown';
		$tierReason = '版本无法对照公告区间';
	} elseif ($axes['version']['state'] === 'affected') {
		$tier = 'red';
		$tierReason = '版本在受影响区间且无 backport 证据';
	} else {
		$lfiState = $axes['lfi_exposure']['state'];
		$pstate = $axes['patch_composition']['state'];
		if ($lfiState === 'sink_found') {
			$tier = 'orange';
			$tierReason = '版本已修，但站点存在 LFI 落点 —— Chain A 可打，与版本无关';
		} elseif ($pstate !== 'pr22113_present') {
			$tier = 'orange';
			$tierReason = '版本已修 OOM，但 patch_composition 无 PR#22113 等价修复（session fixation 守卫缺失）';
		} elseif ($weak > 0) {
			$tier = 'orange';
			$tierReason = '覆盖链里有 ' . $weak . ' 条会重新削弱缓解措施';
		} elseif ($axes['fatal_error_backtraces']['state'] === 'on') {
			$tier = 'orange';
			$tierReason = '8.5.x 上 fatal_error_backtraces 仍为开';
		} elseif ($axes['opcache']['state'] === 'needs_patch') {
			$tier = 'orange';
			$tierReason = 'OPcache 开着且补丁标记缺失';
		} elseif ($lfiState === 'not_scanned') {
			$tier = 'orange';
			$tierReason = 'LFI 落点扫不到（' . $axes['lfi_exposure']['detail'] . '），不能判为缓解到位';
		} else {
			$tier = 'yellow';
			$tierReason = '版本已修 + 无 LFI 落点 + PR#22113 等价 + 缓解到位';
		}
	}

	$labels = array(
		'red' => '未修',
		'orange' => '已修但有残留',
		'yellow' => '已修且缓解到位',
		'unknown' => '判不了',
	);

	return array(
		'axes' => $axes,
		'tier' => $tier,
		'tier_label' => $labels[$tier],
		'tier_reason' => $tierReason,
	);
}

// ---------------------------------------------------------------- 分析 ----

$token = pea_token();
if ($token === null) {
	// 没配令牌 = 没启用，当作不存在。
	pea_out_404();
}
$given = pea_given_token();
if ($given === null || !pea_ct_eq($token, $given)) {
	pea_out_404();
}

if (!headers_sent()) {
	header('Content-Type: text/html; charset=utf-8');
	header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
	header('Pragma: no-cache');
	header('X-Robots-Tag: noindex, nofollow');
	header('Referrer-Policy: no-referrer');
}

$format = isset($_GET['format']) ? strtolower($_GET['format']) : 'json';
if ($format !== 'html' && $format !== 'json') {
	$format = 'json';
}

$phpVersion = PHP_VERSION;
$branch = preg_replace('/^(\d+\.\d+).*$/', '$1', $phpVersion);
$sapi = php_sapi_name();
$sapiFlags = pea_sapi_flags($sapi);

list($markerState, $markerEvidence) = pea_backport_marker();
$ini = pea_ini_report($PEA_KEYS);
$overrides = pea_override_files();

// ---- 判定 ----
$verdict = 'unknown';
$reason = '';
$confidence = 'low';

$fix = isset($PEA_FIXED[$branch]) ? $PEA_FIXED[$branch] : null;

if (!pea_version_parseable($phpVersion)) {
	// 排在所有判定之前：探不到版本时，绝不能顺着下面的分支滑到 patched。
	$verdict = 'unknown';
	$reason = 'php_version_unparseable:' . var_export($phpVersion, true);
	$confidence = 'low';
} elseif ($fix !== null && pea_vcmp($phpVersion, $fix) >= 0) {
	$verdict = 'patched';
	$reason = 'version_at_or_above_branch_fix:' . $fix;
	$confidence = 'high';
} elseif (pea_vcmp($phpVersion, PEA_ADV_MIN) < 0) {
	$verdict = 'patched';
	$reason = 'version_below_affected_range';
	$confidence = 'high';
} elseif (pea_vcmp($phpVersion, PEA_ADV_MAX) <= 0) {
	if ($markerState === 'present') {
		$verdict = 'patched';
		$reason = 'in_vulnerable_range_but_binary_has_backport_marker';
		$confidence = 'medium';
	} elseif ($markerState === 'absent_conclusive') {
		$verdict = 'affected';
		$reason = 'version_in_vulnerable_range_and_binary_lacks_patch_marker';
		$confidence = 'high';
	} else {
		$verdict = 'affected';
		$reason = 'version_in_vulnerable_range_backport_marker_unreadable';
		$confidence = 'medium';
	}
} else {
	$verdict = 'unknown';
	$reason = 'version_above_advisory_range:' . $phpVersion;
	$confidence = 'low';
}

// 覆盖链把缓解措施打开 → 风险上调，但不改版本判定
$weakening = array();
foreach ($overrides as $o) {
	foreach ($o['directives'] as $d) {
		if ($d['effect'] === 'weakens') {
			$weakening[] = $d['file'] . ':' . $d['line'] . ' ' . $d['key'] . '=' . $d['value']
				. ($o['applies_to_me'] ? '' : ' (旁路目录)');
		}
	}
}
if ($weakening && $verdict === 'affected') {
	$reason .= ';per_directory_override_reenables_mitigation';
}

// ---- findings ----
$findings = array();
if ($sapiFlags['mod_php']) {
	$findings[] = array(
		'id' => 'sapi.mod_php',
		'severity' => 'critical',
		'title' => 'mod_php 已加载',
		'detail' => 'mod_php 下 OOM 触发链（Chain D）在应用代码执行前完成，任何 PHP 端点都是入口。这一项优先级最高。',
	);
}
if ($ini['session.upload_progress.enabled']['state'] === 'weak') {
	$findings[] = array(
		'id' => 'ini.upload_progress_on',
		'severity' => 'high',
		'title' => 'session.upload_progress.enabled 是开着的',
		'detail' => '当前值 ' . var_export($ini['session.upload_progress.enabled']['value'], true)
			. '。关掉它能砍掉 CVE-2026-109619 的会话注入面，但挡不住 CVE-2026-109618 的 OOM 链。',
	);
}
if (isset($ini['fatal_error_backtraces']) && $ini['fatal_error_backtraces']['state'] === 'weak') {
	$findings[] = array(
		'id' => 'ini.fatal_error_backtraces_on',
		'severity' => 'high',
		'title' => 'fatal_error_backtraces 是开着的（8.5 分支特有）',
		'detail' => '8.5.x 上这条是 CVE-2026-109619 的第三条臂（backtrace arm）。设为 0。',
	);
}
if ($ini['opcache.enable']['state'] !== 'weak' && strtolower((string)$ini['opcache.enable']['value']) === '1') {
	$findings[] = array(
		'id' => 'opcache.enabled',
		'severity' => 'info',
		'title' => 'OPcache 开着',
		'detail' => 'OPcache 共享内存是 CVE-2026-109619 里没有 INI 开关能关掉的一条臂，只能靠打补丁。',
	);
}
foreach ($weakening as $w) {
	$findings[] = array(
		'id' => 'override.weakens',
		'severity' => 'high',
		'title' => 'per-directory 指令把缓解措施重新打开了',
		'detail' => $w,
	);
}

$warnings = array();
if ($markerState === 'inconclusive') {
	$warnings[] = '读不到 PHP 二进制（open_basedir / disable_functions / 权限 / 被 strip），patch 标记不能作为证据，判定降级为 medium。';
}
if (!empty($_GET['token'])) {
	$warnings[] = '令牌通过查询串传递，已经写进访问日志了。改用 Authorization header。';
}
if (!empty($PEA_EOL_BRANCHES) && in_array($branch, $PEA_EOL_BRANCHES, true) && $verdict !== 'patched') {
	$warnings[] = '分支 ' . $branch . ' 已 EOL，官方不发补丁；只能靠社区 backport 或升级。';
}

// ---- 多轴判定 ----
$ax = pea_axes(array(
	'ver' => $phpVersion,
	'branch' => $branch,
	'fix' => $fix,
	'verdict' => $verdict,
	'markerState' => $markerState,
	'ini' => $ini,
	'overrides' => $overrides,
	'docroot' => isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : null,
	'sapi' => $sapi,
));
$axes = $ax['axes'];
$tier = $ax['tier'];
$tierLabel = $ax['tier_label'];
$tierReason = $ax['tier_reason'];

// Chain A 的正确表述，任何一档都要带上，不许省。
$chainA = '补丁修的是 OOM 和残留状态；upload_progress 的文件名写入是设计如此，配任何应用层 LFI 链子就通，责任在应用层。';

$labelZh = $tierLabel;
if ($tier === 'red') {
	$action = '把 PHP 升到 ' . ($fix !== null ? $fix : '8.5.12') . '。' . $chainA;
} elseif ($tier === 'orange') {
	$action = $tierReason . '。' . $chainA;
} elseif ($tier === 'yellow') {
	$action = $tierReason . '。' . $chainA;
} else {
	$action = '版本无法对照公告区间，用包管理器版本和发行版安全公告人工确认；不要当成安全。';
}

// ---- 三档处置代价 ----
// 与 audit.sh 保持同一形状：[{site, forms_found, endpoints_suspected, options:[...]}, ...]
// probe 只能看到一个 docroot，所以列表里永远只有一项。
$mitigation = array(pea_mitigation($verdict, $phpVersion, $branch, $fix));

$report = array(
	'schema_version' => PEA_SCHEMA_VERSION,
	'tool' => array('name' => 'php-exposure-audit', 'component' => 'probe.php', 'version' => PEA_VERSION),
	'mode' => 'probe',
	'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
	'advisory' => array(
		'cve_ids' => array('CVE-2026-109618', 'CVE-2026-109619'),
		'cvss' => '9.2',
		'affected_range' => array('min' => PEA_ADV_MIN, 'max' => PEA_ADV_MAX),
		'fixed_versions' => $PEA_FIXED,
		'eol_branches_without_official_fix' => $PEA_EOL_BRANCHES,
	),
	// 与 audit.sh 同口径：调用方不用去数 installs 就能判「这次到底查到东西没有」。
	// probe 只查自己一个目标；版本解析不出来时算 0（等于什么都没查到）。
	'targets_found' => pea_version_parseable($phpVersion) ? 1 : 0,
	'verdict' => $verdict,
	'verdict_label_zh' => $labelZh,
	'verdict_reason' => $reason,
	'confidence' => $confidence,
	'exit_code' => $tier === 'red' ? 1 : ($tier === 'unknown' ? 2 : 0),
	'action' => $action,
	'tier' => $tier,
	'tier_label' => $tierLabel,
	'tier_reason' => $tierReason,
	'axes' => $axes,
	'runtime' => array(
		'php_version' => $phpVersion,
		'php_version_id' => PHP_VERSION_ID,
		'php_branch' => $branch,
		'sapi' => $sapi,
		'sapi_flags' => $sapiFlags,
		'os' => PHP_OS,
		'zend_version' => zend_version(),
		'int_size' => PHP_INT_SIZE,
		'php_binary' => PHP_BINARY,
		'document_root' => isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : null,
		'script_filename' => isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : __FILE__,
		'server_software' => isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : null,
	),
	'backport' => array(
		'marker_state' => $markerState,
		'marker_symbol' => $PEA_MARKER_SYM,
		'evidence' => $markerEvidence,
		'note' => 'probe 只能看到自己进程加载的二进制；被 strip 或 open_basedir 挡住时为 inconclusive。',
	),
	'ini' => $ini,
	'coverage_chain' => array(
		'files' => $overrides,
		'weakening_count' => count($weakening),
	),
	'mitigation_impact' => $mitigation,
	'findings' => $findings,
	'warnings' => $warnings,
);

// ---------------------------------------------------------------- 输出 ----

if ($format === 'json') {
	if (!headers_sent()) {
		header('Content-Type: application/json; charset=utf-8');
	}
	$flags = 0;
	if (defined('JSON_PRETTY_PRINT')) {
		$flags |= JSON_PRETTY_PRINT;
	}
	if (defined('JSON_UNESCAPED_UNICODE')) {
		$flags |= JSON_UNESCAPED_UNICODE;
	}
	if (defined('JSON_UNESCAPED_SLASHES')) {
		$flags |= JSON_UNESCAPED_SLASHES;
	}
	echo json_encode($report, $flags), "\n";
	exit;
}

// ---- HTML ----
function pea_h($s)
{
	return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

$sevClass = array('critical' => '#b00020', 'high' => '#d35400', 'info' => '#555');
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>PHP 暴露面自查 · <?php echo pea_h($labelZh); ?></title>
<style>
  body{font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
       margin:0;padding:28px;background:#f6f7f9;color:#1b1f24}
  .wrap{max-width:900px;margin:0 auto}
  .verdict{font-size:34px;font-weight:700;margin:0 0 6px}
  .v-red{color:#b00020}.v-orange{color:#d35400}.v-yellow{color:#0a7b3e}.v-unknown{color:#8a6d00}
  .action{margin:0 0 22px;color:#333}
  .card{background:#fff;border:1px solid #e3e6ea;border-radius:10px;padding:18px 20px;margin:0 0 16px}
  h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:#666;margin:0 0 12px}
  table{width:100%;border-collapse:collapse;font-size:14px}
  th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eef0f3;vertical-align:top}
  th{color:#666;font-weight:600;width:44%}
  code{background:#f2f4f7;padding:1px 5px;border-radius:4px;font-size:13px}
  .weak{color:#b00020;font-weight:600}
  .ok{color:#0a7b3e}
  ul{margin:0;padding-left:20px}
  .meta{color:#777;font-size:13px}
</style>
</head>
<body>
<div class="wrap">
  <p class="verdict v-<?php echo pea_h($tier); ?>"><?php echo pea_h($labelZh); ?></p>
  <p class="action"><?php echo pea_h($action); ?></p>

  <div class="card">
    <h2>判定</h2>
    <table>
      <tr><th>结论</th><td><strong><?php echo pea_h($labelZh); ?></strong>（<?php echo pea_h($verdict); ?>，置信度 <?php echo pea_h($confidence); ?>）</td></tr>
      <tr><th>依据</th><td><code><?php echo pea_h($reason); ?></code></td></tr>
      <tr><th>PHP 版本</th><td><?php echo pea_h($phpVersion); ?>（分支 <?php echo pea_h($branch); ?>）</td></tr>
      <tr><th>SAPI</th><td><?php echo pea_h($sapi); ?><?php if ($sapiFlags['mod_php']) { echo ' <strong class="weak">← mod_php</strong>'; } ?></td></tr>
      <tr><th>patch 标记</th><td><code><?php echo pea_h($markerState); ?></code></td></tr>
      <tr><th>Zend</th><td><?php echo pea_h(zend_version()); ?></td></tr>
    </table>
  </div>

  <div class="card">
    <h2>关键 ini</h2>
    <table>
      <tr><th>指令</th><th>值</th><th>状态</th></tr>
      <?php foreach ($ini as $k => $v) { ?>
      <tr>
        <td><code><?php echo pea_h($k); ?></code><?php if ($v['overridden']) { echo ' <span class="weak">(per-dir 覆盖)</span>'; } ?></td>
        <td><?php echo pea_h($v['value'] === null ? '—' : $v['value']); ?></td>
        <td class="<?php echo $v['state'] === 'weak' ? 'weak' : 'ok'; ?>">
          <?php echo pea_h($v['state']); ?><?php if ($v['advice'] !== null) { echo ' → 建议 ' . pea_h($v['advice']); } ?>
        </td>
      </tr>
      <?php } ?>
    </table>
  </div>

  <?php if ($findings) { ?>
  <div class="card">
    <h2>发现项</h2>
    <ul>
      <?php foreach ($findings as $f) { ?>
      <li style="margin-bottom:8px">
        <strong style="color:<?php echo pea_h($sevClass[$f['severity']]); ?>">[<?php echo pea_h($f['severity']); ?>] <?php echo pea_h($f['title']); ?></strong><br>
        <?php echo pea_h($f['detail']); ?>
      </li>
      <?php } ?>
    </ul>
  </div>
  <?php } ?>

  <?php if ($overrides) { ?>
  <div class="card">
    <h2>覆盖链</h2>
    <?php foreach ($overrides as $o) { ?>
      <p><code><?php echo pea_h($o['file']); ?></code>
        <?php if (!$o['applies_to_me']) { echo '<span class="meta">（旁路目录，不影响本脚本，但影响该目录下的站点）</span>'; } ?></p>
      <ul>
      <?php foreach ($o['directives'] as $d) { ?>
        <li>第 <?php echo (int)$d['line']; ?> 行 <code><?php echo pea_h($d['key']); ?> = <?php echo pea_h($d['value']); ?></code>
            <span class="<?php echo $d['effect'] === 'weakens' ? 'weak' : 'ok'; ?>">[<?php echo pea_h($d['effect']); ?>]</span></li>
      <?php } ?>
      </ul>
    <?php } ?>
  </div>
  <?php } ?>

  <?php if ($warnings) { ?>
  <div class="card">
    <h2>注意</h2>
    <ul><?php foreach ($warnings as $w) { echo '<li>' . pea_h($w) . '</li>'; } ?></ul>
  </div>
  <?php } ?>

  <div class="card">
    <h2>处置选项（三档代价）</h2>
    <?php foreach ($mitigation[0]['options'] as $m) { ?>
      <div style="margin-bottom:18px">
        <p style="margin:0 0 6px">
          <strong><?php echo pea_h(strtoupper(substr($m['id'] === 'upgrade_php' ? 'A' : ($m['id'] === 'block_multipart' ? 'B' : 'C'), 0, 1))); ?>.</strong>
          <strong><?php echo pea_h($m['title']); ?></strong>
          <span class="meta">cost=<?php echo pea_h($m['cost']); ?></span>
        </p>
        <?php if ($m['id'] === 'upgrade_php') { ?>
          <p style="margin:0 0 4px">
            <code><?php echo pea_h($m['from_version']); ?> → <?php echo pea_h($m['to_version'] === null ? '（判不了）' : $m['to_version']); ?></code>
          </p>
          <p style="margin:0"><?php echo pea_h($m['note']); ?></p>
        <?php } elseif ($m['id'] === 'block_multipart') { ?>
          <?php if ($m['blocks']) { ?>
            <p style="margin:0 0 4px">下面这些功能会全废（<?php echo count($m['blocks']); ?> 处）：</p>
            <ul style="margin:0">
            <?php foreach ($m['blocks'] as $b) { ?>
              <li>
                <span class="<?php echo $b['confidence'] === 'high' ? 'weak' : 'ok'; ?>">[<?php echo pea_h($b['confidence']); ?>]</span>
                <code><?php echo pea_h($b['file']); ?><?php echo $b['line'] ? ':' . (int)$b['line'] : ''; ?></code>
                — <?php echo pea_h($b['purpose']); ?>
                <br><span class="meta"><?php echo pea_h($b['evidence']); ?></span>
              </li>
            <?php } ?>
            </ul>
          <?php } else { ?>
            <p style="margin:0">没找到 multipart 表单。</p>
          <?php } ?>
          <?php if (!empty($m['limitation'])) { ?>
            <p class="meta" style="margin:6px 0 0">判不了的地方：<?php echo pea_h($m['limitation']); ?></p>
          <?php } ?>
        <?php } else { ?>
          <p style="margin:0 0 4px"><strong>治：</strong><?php echo pea_h(implode('；', $m['covers'])); ?></p>
          <p style="margin:0 0 4px;color:#b00020"><strong>不治：</strong><?php echo pea_h(implode('；', $m['does_not_cover'])); ?></p>
          <p class="meta" style="margin:0"><?php echo pea_h(implode('；', $m['notes'])); ?></p>
        <?php } ?>
      </div>
    <?php } ?>
  </div>

  <p class="meta">
    php-exposure-audit <?php echo pea_h(PEA_VERSION); ?> · probe.php · <?php echo pea_h($report['generated_at']); ?><br>
    「不中」只代表版本/backport 层面已修，不代表应用没有 LFI（Chain A 在已修补版本上仍可用）。
  </p>
</div>
</body>
</html>
