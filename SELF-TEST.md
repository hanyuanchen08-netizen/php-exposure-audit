# SELF-TEST — PHP 暴露面自查 v0.1.0

这份文件里的每一段都是 **2026-10-22 在本机实际跑出来的终端输出**，不是描述、不是示例。
重新复跑：`cd lab && docker-compose up -d && ./selftest.sh`（令牌从 `lab/.pea-token` 读）。

- 主机：macOS 26.6.2 (arm64) / colima 里的 Docker / colima VM 内部 `Linux 6.8.0-117-generic`
- 靶场 A：`pea-lab-vuln` = PHP 8.5.11 + Apache mod_php（受影响）
- 靶场 B：`pea-lab-fixed` = PHP 8.5.12 + Apache mod_php（官方已修，但链子还通）
- 对照 C：`pea-upoff` = PHP 8.5.12，只把 `session.upload_progress` 关掉
- 对照 D：`pea-nophp` = debian-slim，**一个 PHP 都没有**（假阴性回归）
- A/B 用**同一份 `lab/php.ini`、同一个 webroot**，唯一变量是 PHP 版本
- 结果：**31 PASS / 0 FAIL**

## 判定是三档，不是「中 / 不中」

| 档 | 含义 | 退出码 |
| --- | --- | --- |
| 🔴 未修 | 版本 < 修复线且无 backport / EOL 分支无解 | 1 |
| 🟠 已修但有残留 | 版本达标，但存在 LFI 落点、或无 PR#22113 等价修复、或缓解没到位 | 0 |
| 🟡 已修且缓解到位 | 上述全清 | 0 |
| ⚪ 未发现 PHP | 一个目标都没找到（`not_applicable`） | **2** |
| — 判不了 | 版本无法对照 / 证据冲突（`unknown`） | 2 |

**`not_applicable` 和 `unknown` 必须是两个不同的值**：一个是「没东西可查」，一个是「查了但判不了」。混在一起等于骗人。

**「已修但有残留」退出码是 0，但文案里绝不说「安全」。** CI 不该拿退出码当放行依据——**要看顶层 `verdict`**（`patched_mitigated` 才是真过关，`patched_with_residual` 需人看一眼）。`tier` 只在 `installs[]` 里，顶层没有。

## 验证覆盖了什么

| 要验的点 | 落在哪一节 | 实际结果 |
| --- | --- | --- |
| 能检出 mod_php | 3 / 4 / 5 / 7 | `sapi_flags.mod_php=true` |
| 8.5.11 判未修 | 3 / 5 | `tier=red`，退出码 1 |
| **8.5.12 不得报全绿** | 13 | `tier=orange`，如实报出 3 个 `!!` 项 |
| **patch_composition 判出无 PR#22113** | 13 | `pr22113_absent` |
| **LFI 落点被抓到（含间接式）** | 13 | `sink_found`，2 处 |
| **upload_progress 开/关对照** | 14 | 开着 → `enabled`；关掉 → `disabled` |
| **无 PHP 的机器不说「安全」** | 15 | 首行「未发现 PHP」，exit 2，`targets_found: 0` |
| **`--no-docker` 且没找到时提示漏了容器** | 15 | 有该 warning |
| 无 token 返回 404（与普通 404 无区别） | 2 | 404 / 159 字节 / 同 body |
| 覆盖链能扫出 `.htaccess` + `.user.ini` | 3 / 4 / 5 | 8 条指令，2 条会重开 upload_progress |
| 判不了时老实报 unknown + 退出码 2 | 9 | `unknown` / exit 2 |
| 不用拷文件也能远程跑 | 10 | `bash -s` 管道，exit 1 |
| `.audit-token` 文件模式在真实 HTTP 下可用 | 11 | 无环境变量 → 404；写入文件 → 200 |
| 三档处置代价（`mitigation_impact`） | 12 | 三档齐全、A 给 8.5.12、B 找到 4 个表单、C 明说不管 109618 |
| B 档不把工具自身当成上传表单 | 12 | 0 次误报 |

## 修掉的那个硬伤（第 15 节）

曾经的样子：

```
$ ./audit.sh --no-docker          # 这台 Mac 上根本没有 PHP
不中
版本已在修复线以上，无需动作；保持自动安全更新……

PHP 安装数 : 0   受影响 0 / 已修 0 / 判不了 0
=== EXIT: 0 ===
```

`total=0` 落进了 `else` 分支，被判成 `patched`。**在最常见的场景（扫错机器 / 容器在别的 host / PHP 装在非标准路径）下，它给了客户一句「你安全」。** 假阴性比漏检更危险——客户拿着这句话就走了。

现在的样子：

```
$ ./audit.sh --no-docker
未发现 PHP
本机未找到任何 PHP 安装。如果 PHP 跑在容器 / 另一台机器 / 非标准路径，请加 --root 或 --docker-only，或直接对那台机器跑。不要因为“没找到”就当安全。
=== EXIT: 2 ===
```

顺手把同类的第二处也堵了：`probe.php` 里 `pea_ver_num('')` 返回 0，而 `0 < 5.4.0` 会让判定落到 `below_affected_range` → `patched`。探不到自己版本时同样会说「安全」。现在加了 `pea_version_parseable()` 前置守卫，不可解析一律 `unknown`。

## 七轴逐项输出（8.5.12 靶场的真实结果）

版本那一格是 `patched`、整体却是橙色 —— 这就是「补了洞，链子还通」的样子：

```
tier        : orange / 已修但有残留
tier_reason : 版本已修，但站点存在 LFI 落点 —— Chain A 可打，与版本无关
  version                  patched          8.5.12
  patch_composition        pr22113_absent   8.5.12 是上游修复版，PR#22113 未合并，源码里没有该守卫
  upload_progress          enabled          session.upload_progress.enabled=1
  lfi_exposure             sink_found       2 处可疑 include/文件读取
  serializer_reset         not_applicable   当前 SAPI 不是 FPM
  fatal_error_backtraces   on               fatal_error_backtraces=1（8.5.x 须为 0）
  opcache                  covered          OPcache 开着，补丁标记在
```

## 完整实跑输出

```

----------------------------------------------------------------
0. 环境

----------------------------------------------------------------
$ docker ps --format "{{.Names}}\t{{.Status}}\t{{.Ports}}"
pea-lab-vuln	Up 2 minutes (healthy)	0.0.0.0:18091->80/tcp, [::]:18091->80/tcp
pea-lab-fixed	Up 2 minutes (healthy)	0.0.0.0:18092->80/tcp, [::]:18092->80/tcp

----------------------------------------------------------------
1. 靶场在线

----------------------------------------------------------------
$ curl -s http://127.0.0.1:18091/index.php
lab ok
PHP 8.5.11
SAPI apache2handler
upload_progress 1
$ curl -s http://127.0.0.1:18092/index.php
lab ok
PHP 8.5.12
SAPI apache2handler
upload_progress 1

----------------------------------------------------------------
2. probe.php 鉴权：无 token 必须是 404

----------------------------------------------------------------
$ curl -si http://127.0.0.1:18091/probe.php | head -1
HTTP/1.1 404 Not Found
  [PASS] 无 token → 404                              404
$ curl -s -o /dev/null -w '%{http_code}' -H 'X-Audit-Token: wrong' .../probe.php
  [PASS] 错 token → 404                              404
$ curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer '$TOKEN .../probe.php
  [PASS] Bearer token → 200                           200
$ curl -s .../probe.php  （404 body，应和 Apache 默认 404 无区别）
<!DOCTYPE html>
<html><head><title>404 Not Found</title></head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>

----------------------------------------------------------------
3. probe.php 判 affected —— PHP 8.5.11 + mod_php

----------------------------------------------------------------
$ curl -s -H 'X-Audit-Token: ...' 'http://127.0.0.1:18091/probe.php?format=json' | python3 -m json.tool
{
    "schema_version": "1.0",
    "tool": {
        "name": "php-exposure-audit",
        "component": "probe.php",
        "version": "0.1.0"
    },
    "mode": "probe",
    "generated_at": "2026-10-22T09:04:14Z",
    "advisory": {
        "cve_ids": [
            "CVE-2026-109618",
            "CVE-2026-109619"
        ],
        "cvss": "9.2",
        "affected_range": {
            "min": "5.4.0",
            "max": "8.5.11"
        },
        "fixed_versions": {
            "8.2": "8.2.35",
            "8.3": "8.3.36",
            "8.4": "8.4.27",
            "8.5": "8.5.12"
        },
        "eol_branches_without_official_fix": [
            "5.4",
            "5.5",
            "5.6",
            "7.0",
            "7.1",
            "7.2",
            "7.3",
            "7.4",
            "8.0",
            "8.1"
        ]
    },
    "targets_found": 1,
    "verdict": "affected",
    "verdict_label_zh": "\u672a\u4fee",
    "verdict_reason": "version_in_vulnerable_range_and_binary_lacks_patch_marker;per_directory_override_reenables_mitigation",
    "confidence": "high",
    "exit_code": 1,
    "action": "\u628a PHP \u5347\u5230 8.5.12\u3002\u8865\u4e01\u4fee\u7684\u662f OOM \u548c\u6b8b\u7559\u72b6\u6001\uff1bupload_progress \u7684\u6587\u4ef6\u540d\u5199\u5165\u662f\u8bbe\u8ba1\u5982\u6b64\uff0c\u914d\u4efb\u4f55\u5e94\u7528\u5c42 LFI \u94fe\u5b50\u5c31\u901a\uff0c\u8d23\u4efb\u5728\u5e94\u7528\u5c42\u3002",
    "tier": "red",
    "tier_label": "\u672a\u4fee",
    "tier_reason": "\u7248\u672c\u5728\u53d7\u5f71\u54cd\u533a\u95f4\u4e14\u65e0 backport \u8bc1\u636e",
    "axes": {
        "version": {
            "state": "affected",
            "detail": "8.5.11"
        },
        "patch_composition": {
            "state": "unknown",
            "detail": "probe \u8bfb\u4e0d\u5230\u5305\u8865\u4e01\u5217\u8868\uff08\u81ea\u7f16\u8bd1/\u955c\u50cf/\u65e0\u5305\u4fe1\u606f\uff09\uff0c\u5224\u4e0d\u4e86\u662f\u5426\u542b PR#22113 \u7b49\u4ef7\u4fee\u590d"
        },
        "upload_progress": {
            "state": "enabled",
            "detail": "session.upload_progress.enabled=1"
        },
        "lfi_exposure": {
            "state": "sink_found",
            "detail": "2 \u5904\u53ef\u7591 include/\u6587\u4ef6\u8bfb\u53d6\uff08\u9759\u6001\u626b\u63cf\uff0c\u9700\u4eba\u5de5\u786e\u8ba4\u662f\u5426\u771f\u53ef\u63a7\uff09",
            "sinks": [
                {
                    "file": "/var/www/html/app/download.php",
                    "line": 3,
                    "kind": "indirect($f)",
                    "evidence": "readfile($f); <= $f = $_REQUEST['file'];"
                },
                {
                    "file": "/var/www/html/app/view.php",
                    "line": 4,
                    "kind": "indirect($tpl)",
                    "evidence": "include $tpl . '.php'; <= $tpl = $_GET['tpl'];"
                }
            ]
        },
        "serializer_reset": {
            "state": "not_applicable",
            "detail": "\u5f53\u524d SAPI \u4e0d\u662f FPM"
        },
        "fatal_error_backtraces": {
            "state": "on",
            "detail": "fatal_error_backtraces=1\uff088.5.x \u987b\u4e3a 0\uff09"
        },
        "opcache": {
            "state": "needs_patch",
            "detail": "OPcache \u5f00\u7740\u4e14\u8865\u4e01\u6807\u8bb0\u7f3a\u5931\uff0c\u5171\u4eab\u5185\u5b58\u662f\u4e00\u6761\u5173\u4e0d\u6389\u7684\u81c2"
        }
    },
    "runtime": {
        "php_version": "8.5.11",
        "php_version_id": 80511,
        "php_branch": "8.5",
        "sapi": "apache2handler",
        "sapi_flags": {
            "mod_php": true,
            "fpm": false,
            "cgi": false,
            "cli": false,
            "litespeed": false,
            "frankenphp": false
        },
        "os": "Linux",
        "zend_version": "4.5.11",
        "int_size": 8,
        "php_binary": "",
        "document_root": "/var/www/html",
        "script_filename": "/var/www/html/probe.php",
        "server_software": "Apache/2.4.69 (Debian)"
    },
    "backport": {
        "marker_state": "absent_conclusive",
        "marker_symbol": "php_basic_early_rinit",
        "evidence": [
            "stripped:/usr/sbin/apache2",
            "no-marker:/usr/lib/apache2/modules/libphp.so"
        ],
        "note": "probe \u53ea\u80fd\u770b\u5230\u81ea\u5df1\u8fdb\u7a0b\u52a0\u8f7d\u7684\u4e8c\u8fdb\u5236\uff1b\u88ab strip \u6216 open_basedir \u6321\u4f4f\u65f6\u4e3a inconclusive\u3002"
    },
    "ini": {
        "session.upload_progress.enabled": {
            "value": "1",
            "global_value": "1",
            "local_value": "1",
            "access": 2,
            "overridden": false,
            "state": "weak",
            "advice": "0"
        },
        "session.upload_progress.cleanup": {
            "value": "1",
            "global_value": "1",
            "local_value": "1",
            "access": 2,
            "overridden": false,
            "state": "info",
            "advice": null
        },
        "post_max_size": {
            "value": "256M",
            "global_value": "256M",
            "local_value": "256M",
            "access": 6,
            "overridden": false,
            "state": "info",
            "advice": null
        },
        "upload_max_filesize": {
            "value": "256M",
            "global_value": "256M",
            "local_value": "256M",
            "access": 6,
            "overridden": false,
            "state": "info",
            "advice": null
        },
        "memory_limit": {
            "value": "32M",
            "global_value": "32M",
            "local_value": "32M",
            "access": 7,
            "overridden": false,
            "state": "info",
            "advice": null
        },
        "fatal_error_backtraces": {
            "value": "1",
            "global_value": "1",
            "local_value": "1",
            "access": 7,
            "overridden": false,
            "state": "weak",
            "advice": "0"
        },
        "session.use_only_cookies": {
            "value": "1",
            "global_value": "1",
            "local_value": "1",
            "access": 7,
            "overridden": false,
            "state": "info",
            "advice": null
        },
        "session.serialize_handler": {
            "value": "php",
            "global_value": "php",
            "local_value": "php",
            "access": 7,
            "overridden": false,
            "state": "info",
            "advice": null
        },
        "opcache.enable": {
            "value": "1",
            "global_value": "1",
            "local_value": "1",
            "access": 7,
            "overridden": false,
            "state": "info",
            "advice": null
        }
    },
    "coverage_chain": {
        "files": [
            {
                "file": "/var/www/html/legacy/.htaccess",
                "applies_to_me": false,
                "directives": [
                    {
                        "file": "/var/www/html/legacy/.htaccess",
                        "line": 4,
                        "key": "session.upload_progress.enabled",
                        "value": "On",
                        "effect": "weakens"
                    },
                    {
                        "file": "/var/www/html/legacy/.htaccess",
                        "line": 5,
                        "key": "memory_limit",
                        "value": "64M",
                        "effect": "raises"
                    },
                    {
                        "file": "/var/www/html/legacy/.htaccess",
                        "line": 6,
                        "key": "post_max_size",
                        "value": "512M",
                        "effect": "raises"
                    },
                    {
                        "file": "/var/www/html/legacy/.htaccess",
                        "line": 10,
                        "key": "session.upload_progress.enabled",
                        "value": "On",
                        "effect": "weakens"
                    },
                    {
                        "file": "/var/www/html/legacy/.htaccess",
                        "line": 11,
                        "key": "memory_limit",
                        "value": "64M",
                        "effect": "raises"
                    },
                    {
                        "file": "/var/www/html/legacy/.htaccess",
                        "line": 12,
                        "key": "post_max_size",
                        "value": "512M",
                        "effect": "raises"
                    }
                ]
            },
            {
                "file": "/var/www/html/uploads/.user.ini",
                "applies_to_me": false,
                "directives": [
                    {
                        "file": "/var/www/html/uploads/.user.ini",
                        "line": 3,
                        "key": "post_max_size",
                        "value": "128M",
                        "effect": "raises"
                    },
                    {
                        "file": "/var/www/html/uploads/.user.ini",
                        "line": 4,
                        "key": "upload_max_filesize",
                        "value": "128M",
                        "effect": "raises"
                    },
                    {
                        "file": "/var/www/html/uploads/.user.ini",
                        "line": 5,
                        "key": "session.serialize_handler",
                        "value": "php_serialize",
                        "effect": "neutral"
                    }
                ]
            }
        ],
        "weakening_count": 2
    },
    "mitigation_impact": [
        {
            "site": "/var/www/html",
            "forms_found": 4,
            "endpoints_suspected": 0,
            "options": [
                {
                    "id": "upgrade_php",
                    "title": "\u5347\u7ea7 PHP",
                    "cost": "low",
                    "from_version": "8.5.11",
                    "to_version": "8.5.12",
                    "note": "\u5347\u7ea7\u5230\u540c\u5206\u652f\u4fee\u590d\u7248\uff1b\u4e0d\u6539\u4ee3\u7801\u3001\u4e0d\u6539\u914d\u7f6e\u3002",
                    "blocks": [],
                    "notes": [
                        "\u4e0d\u6539\u4ee3\u7801\u3001\u4e0d\u6539\u914d\u7f6e",
                        "\u552f\u4e00\u5b8c\u6574\u4fee\u590d"
                    ]
                },
                {
                    "id": "block_multipart",
                    "title": "Web \u5c42 403 multipart",
                    "cost": "high",
                    "blocks": [
                        {
                            "file": "/var/www/html/blog/profile.php",
                            "line": 1,
                            "kind": "form_multipart",
                            "confidence": "high",
                            "purpose": "\u5934\u50cf\u4e0a\u4f20",
                            "evidence": "<form method=\"post\" enctype=\"multipart/form-data\"><input type=\"file\" name=\"avatar\"></form>"
                        },
                        {
                            "file": "/var/www/html/blog/wp-admin-async.php",
                            "line": 0,
                            "kind": "wp_media",
                            "confidence": "high",
                            "purpose": "\u7591\u4f3c\u4e0a\u4f20\uff08\u8def\u5f84\u548c\u5b57\u6bb5\u540d\u90fd\u770b\u4e0d\u51fa\u7528\u9014\uff09",
                            "evidence": "file input / FormData / WordPress \u4e0a\u4f20\u5165\u53e3\uff08\u65e0 enctype\uff09"
                        },
                        {
                            "file": "/var/www/html/shop/product-edit.php",
                            "line": 1,
                            "kind": "form_multipart",
                            "confidence": "high",
                            "purpose": "\u5546\u54c1\u56fe\u4e0a\u4f20",
                            "evidence": "<form action=\"/admin/save.php\" method=\"post\" enctype=\"multipart/form-data\">"
                        },
                        {
                            "file": "/var/www/html/shop/admin/logo.php",
                            "line": 1,
                            "kind": "form_multipart",
                            "confidence": "high",
                            "purpose": "Logo \u4e0a\u4f20",
                            "evidence": "<form method=\"post\" enctype=\"multipart/form-data\"><input type=\"file\" name=\"logo_file\"></form>"
                        }
                    ],
                    "suspected_endpoints": [],
                    "scanned_files": 0,
                    "truncated": false,
                    "limitation": null,
                    "notes": [
                        "\u4e0d\u53d1\u8d77\u4efb\u4f55\u8bf7\u6c42\uff0c\u53ea\u8bfb\u6587\u4ef6",
                        "403 \u6389 multipart \u4f1a\u540c\u65f6\u5e9f\u6389\u5546\u54c1\u56fe / \u7ed3\u8d26\u7b49\u4e0a\u4f20",
                        "probe \u53ea\u770b\u5f97\u5230\u81ea\u5df1\u7684 docroot\uff0c\u5176\u4ed6 vhost \u9700\u7528 audit.sh"
                    ]
                },
                {
                    "id": "disable_upload_progress",
                    "title": "\u53ea\u5173 session.upload_progress",
                    "cost": "low",
                    "covers": [
                        "CVE-2026-109619 \u7684 session \u6ce8\u5165\u8def\u5f84"
                    ],
                    "does_not_cover": [
                        "CVE-2026-109618\uff08Zend \u5f15\u64ce OOM\uff0c\u4e0e upload_progress \u65e0\u5173\uff09",
                        "8.5.x \u7684 fatal_error_backtraces \u81c2\uff08\u9700\u5355\u72ec\u8bbe 0\uff09"
                    ],
                    "blocks": [],
                    "notes": [
                        "\u4e0d\u662f\u5b8c\u6574\u4fee\u590d",
                        "\u4efb\u4f55\u8d85\u5927 multipart POST \u4ecd\u80fd\u89e6\u53d1 109618 \u7684 OOM",
                        "\u8986\u76d6\u94fe\u91cc\u7684 .htaccess / .user.ini \u53ef\u80fd\u628a\u5b83\u91cd\u65b0\u6253\u5f00"
                    ]
                }
            ]
        }
    ],
    "findings": [
        {
            "id": "sapi.mod_php",
            "severity": "critical",
            "title": "mod_php \u5df2\u52a0\u8f7d",
            "detail": "mod_php \u4e0b OOM \u89e6\u53d1\u94fe\uff08Chain D\uff09\u5728\u5e94\u7528\u4ee3\u7801\u6267\u884c\u524d\u5b8c\u6210\uff0c\u4efb\u4f55 PHP \u7aef\u70b9\u90fd\u662f\u5165\u53e3\u3002\u8fd9\u4e00\u9879\u4f18\u5148\u7ea7\u6700\u9ad8\u3002"
        },
        {
            "id": "ini.upload_progress_on",
            "severity": "high",
            "title": "session.upload_progress.enabled \u662f\u5f00\u7740\u7684",
            "detail": "\u5f53\u524d\u503c '1'\u3002\u5173\u6389\u5b83\u80fd\u780d\u6389 CVE-2026-109619 \u7684\u4f1a\u8bdd\u6ce8\u5165\u9762\uff0c\u4f46\u6321\u4e0d\u4f4f CVE-2026-109618 \u7684 OOM \u94fe\u3002"
        },
        {
            "id": "ini.fatal_error_backtraces_on",
            "severity": "high",
            "title": "fatal_error_backtraces \u662f\u5f00\u7740\u7684\uff088.5 \u5206\u652f\u7279\u6709\uff09",
            "detail": "8.5.x \u4e0a\u8fd9\u6761\u662f CVE-2026-109619 \u7684\u7b2c\u4e09\u6761\u81c2\uff08backtrace arm\uff09\u3002\u8bbe\u4e3a 0\u3002"
        },
        {
            "id": "opcache.enabled",
            "severity": "info",
            "title": "OPcache \u5f00\u7740",
            "detail": "OPcache \u5171\u4eab\u5185\u5b58\u662f CVE-2026-109619 \u91cc\u6ca1\u6709 INI \u5f00\u5173\u80fd\u5173\u6389\u7684\u4e00\u6761\u81c2\uff0c\u53ea\u80fd\u9760\u6253\u8865\u4e01\u3002"
        },
        {
            "id": "override.weakens",
            "severity": "high",
            "title": "per-directory \u6307\u4ee4\u628a\u7f13\u89e3\u63aa\u65bd\u91cd\u65b0\u6253\u5f00\u4e86",
            "detail": "/var/www/html/legacy/.htaccess:4 session.upload_progress.enabled=On (\u65c1\u8def\u76ee\u5f55)"
        },
        {
            "id": "override.weakens",
            "severity": "high",
            "title": "per-directory \u6307\u4ee4\u628a\u7f13\u89e3\u63aa\u65bd\u91cd\u65b0\u6253\u5f00\u4e86",
            "detail": "/var/www/html/legacy/.htaccess:10 session.upload_progress.enabled=On (\u65c1\u8def\u76ee\u5f55)"
        }
    ],
    "warnings": []
}
  [PASS] 8.5.11 probe verdict                           affected
  [PASS] 8.5.11 检出 mod_php                          True
  [PASS] 报出 upload_progress 当前值               1

----------------------------------------------------------------
4. probe.php 判 patched —— PHP 8.5.12 + mod_php

----------------------------------------------------------------
$ curl -s -H 'X-Audit-Token: ...' 'http://127.0.0.1:18092/probe.php?format=json'
  （全量 JSON 见第 3 节，字段结构一致；这里只摘判定相关字段，都是原样输出）
verdict      : patched / 已修但有残留 | confidence high | exit 0
reason       : version_at_or_above_branch_fix:8.5.12
php_version  : 8.5.12
sapi         : apache2handler mod_php= True
marker_state : present
evidence     : ['stripped:/usr/sbin/apache2', 'marker:/usr/lib/apache2/modules/libphp.so']
upload_prog  : 1 ( weak )
backtraces   : 1 ( weak )
chain        : 2 files, weakening 2
action       : 版本已修，但站点存在 LFI 落点 —— Chain A 可打，与版本无关。补丁修的是 OOM 和残留状态；upload_progress 的文件名写入是设计如此，配任何应用层 LFI 链子就通，责任在应用层。
  [PASS] 8.5.12 probe verdict                           patched

----------------------------------------------------------------
5. audit.sh 在受影响容器内（8.5.11 / mod_php）

----------------------------------------------------------------
$ docker cp audit.sh pea-lab-vuln:/tmp/audit.sh
$ docker exec pea-lab-vuln bash /tmp/audit.sh --no-docker
未修
把 PHP 升到 8.5.12（或同分支 8.2.35 / 8.3.36 / 8.4.27）。补丁修的是 OOM 和残留状态；upload_progress 的文件名写入是设计如此，配任何应用层 LFI 链子就通，责任在应用层。

----------------------------------------------------------------
php-exposure-audit v0.1.0   CVE-2026-109618 / CVE-2026-109619 (CVSS 9.2)
主机 1c7efd5f1be6 · Linux 6.8.0-117-generic · 2026-10-22T09:04:14Z
----------------------------------------------------------------
PHP 安装数 : 1   未修 1 / 已修但有残留 0 / 已修且缓解到位 0
mod_php    : 有（Chain D，无需应用代码即可触发）

--- [1/1] PHP 8.5.11   /usr/local/bin/php ---
结论        : 未修
原因        : 版本在受影响区间且无 backport 证据
七轴检查    :
  !! version                  affected           8.5.11
  ?? patch_composition        unknown            自编译或官方镜像，读不到包补丁列表，判不了是否含 PR#22113 等价修复
  !! upload_progress          enabled            session.upload_progress.enabled=1
  !! lfi_exposure             sink_found         站点级（全部 webroot 扫一次）：2 处可疑 include/文件读取（静态扫描，需人工确认是否真可控）
  ok serializer_reset         not_applicable     FPM 跨请求残留状态（OOM 补丁覆盖即修）
  !! fatal_error_backtraces   on                 仅 8.5.x；须为 0
  !! opcache                  needs_patch        OPcache 共享内存是 109619 里关不掉的一条臂
版本判定    : affected (version_in_vulnerable_range)
backport    : marker=absent_conclusive  changelog=未命中
SAPI        : 可用[apache2handler]  运行中[apache2handler]   <<< mod_php
构建时间    : Oct 21 2026 00:26:24
关键 ini    :
  [generic] /usr/local/etc/php/php.ini
    session.upload_progress.enabled    = 1            (建议 0)  << 弱
    session.upload_progress.cleanup    = 1           
    post_max_size                      = 256M        
    upload_max_filesize                = 256M        
    memory_limit                       = 32M         
    fatal_error_backtraces             = 1            (建议 0)  << 弱
    session.use_only_cookies           = 1           
    session.serialize_handler          = php         
    opcache.enable                     = 1           
备注        :
  - mod_php 已加载：应用代码未执行即可触发（Chain D），优先级最高
发现项      :
  [critical] mod_php 已加载
         mod_php 下 OOM 触发链（Chain D）在应用代码执行前完成，任何 PHP 端点都是入口。这一项优先级最高。
  [high] session.upload_progress.enabled 是开着的
         当前值 1。关掉它能砍掉 CVE-2026-109619 的会话注入面，但挡不住 CVE-2026-109618 的 OOM 链。
  [high] fatal_error_backtraces 是开着的（8.5 分支特有）
         8.5.x 上这条是 CVE-2026-109619 的第三条臂（backtrace arm）。设为 0。
  [info] OPcache 开着
         OPcache 共享内存是 CVE-2026-109619 里没有 INI 开关能关掉的一条臂，只能靠打补丁。

--- 覆盖链 ---
共 8 条 per-directory PHP 指令
  /var/www/html/legacy/.htaccess:10  php_flag session.upload_progress.enabled On  [weakens]
  /var/www/html/legacy/.htaccess:11  php_value memory_limit 64M  [raises]
  /var/www/html/legacy/.htaccess:12  php_value post_max_size 512M  [raises]
  /var/www/html/legacy/.htaccess:4  php_flag session.upload_progress.enabled On  [weakens]
  /var/www/html/legacy/.htaccess:5  php_value memory_limit 64M  [raises]
  /var/www/html/legacy/.htaccess:6  php_value post_max_size 512M  [raises]
  /var/www/html/uploads/.user.ini:3  post_max_size = 128M  [raises]
  /var/www/html/uploads/.user.ini:4  upload_max_filesize = 128M  [raises]
其中 2 条会把 session.upload_progress / fatal_error_backtraces 重新打开

--- 处置选项（三档代价）· /var/www/html ---
A. 升级 PHP
   8.5.11 → 8.5.12
   升级到同分支修复版；不改代码、不改配置。
   代价：不改代码、不改配置。唯一完整修复。
B. Web 层 403 multipart
   代价：下面这些功能会全废（4 处）
     [high] /shop/admin/logo.php:1  Logo 上传
          <form method="post" enctype="multipart/form-data"><input type="file" name="logo_file"></form>
     [high] /shop/product-edit.php:1  商品图上传
          <form action="/admin/save.php" method="post" enctype="multipart/form-data">
     [high] /blog/wp-admin-async.php:1  WordPress 媒体库上传
          <script>var x = '/wp-admin/async-upload.php';</script>
     [high] /blog/profile.php:1  头像上传
          <form method="post" enctype="multipart/form-data"><input type="file" name="avatar"></form>
C. 只关 session.upload_progress（+ fatal_error_backtraces）
   治：CVE-2026-109619 的 session 注入路径。
   不治：CVE-2026-109618（Zend 引擎 OOM）—— 这条跟 upload_progress 无关，
         任何超大 multipart POST 都能触发。
   8.5.x 还要一起关 fatal_error_backtraces=0（第三条臂）。
   代价：大多数应用不用 upload_progress，关掉一般无感。
         但如果覆盖链里有 .htaccess / .user.ini 把它又打开，先清掉。

--- 说明 ---
  · 本工具只读：不写配置、不改文件、不发外部请求。
  · "不中" 只代表版本/backport 层面已修，不代表应用没有 LFI（Chain A 在已修补版本上仍可用）。
  · 缓解措施（关 upload_progress、关 backtraces）只能降风险，唯一完整修复是升级。
exit code: 1
  [PASS] audit.sh 8.5.11 退出码                      1

----------------------------------------------------------------
6. audit.sh 在已修容器内（8.5.12 / mod_php）

----------------------------------------------------------------
$ docker cp audit.sh pea-lab-fixed:/tmp/audit.sh
$ docker exec pea-lab-fixed bash /tmp/audit.sh --no-docker
已修但有残留
版本已修，但站点存在 LFI 落点 —— Chain A 可打，与版本无关。补丁修的是 OOM 和残留状态；upload_progress 的文件名写入是设计如此，配任何应用层 LFI 链子就通，责任在应用层。

----------------------------------------------------------------
php-exposure-audit v0.1.0   CVE-2026-109618 / CVE-2026-109619 (CVSS 9.2)
主机 fb00c846a5de · Linux 6.8.0-117-generic · 2026-10-22T09:04:15Z
----------------------------------------------------------------
PHP 安装数 : 1   未修 0 / 已修但有残留 1 / 已修且缓解到位 0
mod_php    : 有（Chain D，无需应用代码即可触发）

--- [1/1] PHP 8.5.12   /usr/local/bin/php ---
结论        : 已修但有残留
原因        : 版本已修，但站点存在 LFI 落点 —— Chain A 可打，与版本无关
七轴检查    :
  ok version                  patched            8.5.12
  !! patch_composition        pr22113_absent     8.5.12 是上游修复版（自编译/官方镜像），PR#22113 未合并，源码里没有该守卫
  !! upload_progress          enabled            session.upload_progress.enabled=1
  !! lfi_exposure             sink_found         站点级（全部 webroot 扫一次）：2 处可疑 include/文件读取（静态扫描，需人工确认是否真可控）
  ok serializer_reset         not_applicable     FPM 跨请求残留状态（OOM 补丁覆盖即修）
  !! fatal_error_backtraces   on                 仅 8.5.x；须为 0
  ok opcache                  covered            OPcache 共享内存是 109619 里关不掉的一条臂
版本判定    : patched (version_at_or_above_branch_fix:8.5.12)
backport    : marker=present  changelog=未命中
SAPI        : 可用[apache2handler]  运行中[apache2handler]   <<< mod_php
构建时间    : Oct 21 2026 15:54:27
关键 ini    :
  [generic] /usr/local/etc/php/php.ini
    session.upload_progress.enabled    = 1            (建议 0)  << 弱
    session.upload_progress.cleanup    = 1           
    post_max_size                      = 256M        
    upload_max_filesize                = 256M        
    memory_limit                       = 32M         
    fatal_error_backtraces             = 1            (建议 0)  << 弱
    session.use_only_cookies           = 1           
    session.serialize_handler          = php         
    opcache.enable                     = 1           
备注        :
  - mod_php 已加载：应用代码未执行即可触发（Chain D），优先级最高
发现项      :
  [critical] mod_php 已加载
         mod_php 下 OOM 触发链（Chain D）在应用代码执行前完成，任何 PHP 端点都是入口。这一项优先级最高。
  [high] session.upload_progress.enabled 是开着的
         当前值 1。关掉它能砍掉 CVE-2026-109619 的会话注入面，但挡不住 CVE-2026-109618 的 OOM 链。
  [high] fatal_error_backtraces 是开着的（8.5 分支特有）
         8.5.x 上这条是 CVE-2026-109619 的第三条臂（backtrace arm）。设为 0。
  [info] OPcache 开着
         OPcache 共享内存是 CVE-2026-109619 里没有 INI 开关能关掉的一条臂，只能靠打补丁。

--- 覆盖链 ---
共 8 条 per-directory PHP 指令
  /var/www/html/legacy/.htaccess:10  php_flag session.upload_progress.enabled On  [weakens]
  /var/www/html/legacy/.htaccess:11  php_value memory_limit 64M  [raises]
  /var/www/html/legacy/.htaccess:12  php_value post_max_size 512M  [raises]
  /var/www/html/legacy/.htaccess:4  php_flag session.upload_progress.enabled On  [weakens]
  /var/www/html/legacy/.htaccess:5  php_value memory_limit 64M  [raises]
  /var/www/html/legacy/.htaccess:6  php_value post_max_size 512M  [raises]
  /var/www/html/uploads/.user.ini:3  post_max_size = 128M  [raises]
  /var/www/html/uploads/.user.ini:4  upload_max_filesize = 128M  [raises]
其中 2 条会把 session.upload_progress / fatal_error_backtraces 重新打开

--- 处置选项（三档代价）· /var/www/html ---
A. 升级 PHP
   8.5.12 → 8.5.12
   已在这条分支的修复线以上，无需升级。
   代价：不改代码、不改配置。唯一完整修复。
B. Web 层 403 multipart
   代价：下面这些功能会全废（4 处）
     [high] /shop/admin/logo.php:1  Logo 上传
          <form method="post" enctype="multipart/form-data"><input type="file" name="logo_file"></form>
     [high] /shop/product-edit.php:1  商品图上传
          <form action="/admin/save.php" method="post" enctype="multipart/form-data">
     [high] /blog/wp-admin-async.php:1  WordPress 媒体库上传
          <script>var x = '/wp-admin/async-upload.php';</script>
     [high] /blog/profile.php:1  头像上传
          <form method="post" enctype="multipart/form-data"><input type="file" name="avatar"></form>
C. 只关 session.upload_progress（+ fatal_error_backtraces）
   治：CVE-2026-109619 的 session 注入路径。
   不治：CVE-2026-109618（Zend 引擎 OOM）—— 这条跟 upload_progress 无关，
         任何超大 multipart POST 都能触发。
   8.5.x 还要一起关 fatal_error_backtraces=0（第三条臂）。
   代价：大多数应用不用 upload_progress，关掉一般无感。
         但如果覆盖链里有 .htaccess / .user.ini 把它又打开，先清掉。

--- 说明 ---
  · 本工具只读：不写配置、不改文件、不发外部请求。
  · "不中" 只代表版本/backport 层面已修，不代表应用没有 LFI（Chain A 在已修补版本上仍可用）。
  · 缓解措施（关 upload_progress、关 backtraces）只能降风险，唯一完整修复是升级。
exit code: 0
  [PASS] audit.sh 8.5.12 退出码                      0

----------------------------------------------------------------
7. audit.sh --json（受影响容器，完整 schema）

----------------------------------------------------------------
$ docker exec pea-lab-vuln bash /tmp/audit.sh --no-docker --json | python3 -m json.tool
{
    "schema_version": "1.0",
    "tool": {
        "name": "php-exposure-audit",
        "component": "audit.sh",
        "version": "0.1.0"
    },
    "generated_at": "2026-10-22T09:04:15Z",
    "host": {
        "hostname": "1c7efd5f1be6",
        "os": "Linux",
        "kernel": "6.8.0-117-generic"
    },
    "advisory": {
        "cve_ids": [
            "CVE-2026-109618",
            "CVE-2026-109619"
        ],
        "cvss": "9.2",
        "affected_range": {
            "min": "5.4.0",
            "max": "8.5.11"
        },
        "fixed_versions": {
            "8.2": "8.2.35",
            "8.3": "8.3.36",
            "8.4": "8.4.27",
            "8.5": "8.5.12"
        },
        "eol_branches_without_official_fix": [
            "5.4",
            "5.5",
            "5.6",
            "7.0",
            "7.1",
            "7.2",
            "7.3",
            "7.4",
            "8.0",
            "8.1"
        ]
    },
    "verdict": "affected",
    "verdict_label_zh": "\u672a\u4fee",
    "action": "\u628a PHP \u5347\u5230 8.5.12\uff08\u6216\u540c\u5206\u652f 8.2.35 / 8.3.36 / 8.4.27\uff09\u3002\u8865\u4e01\u4fee\u7684\u662f OOM \u548c\u6b8b\u7559\u72b6\u6001\uff1bupload_progress \u7684\u6587\u4ef6\u540d\u5199\u5165\u662f\u8bbe\u8ba1\u5982\u6b64\uff0c\u914d\u4efb\u4f55\u5e94\u7528\u5c42 LFI \u94fe\u5b50\u5c31\u901a\uff0c\u8d23\u4efb\u5728\u5e94\u7528\u5c42\u3002",
    "exit_code": 1,
    "targets_found": 1,
    "summary": {
        "install_count": 1,
        "affected": 1,
        "patched": 0,
        "unknown": 0,
        "mod_php_present": true,
        "docker_containers_with_php": 0,
        "docker_affected": 0,
        "docker_patched": 0,
        "docker_unknown": 0,
        "total_targets": 1
    },
    "installs": [
        {
            "binary": "/usr/local/bin/php",
            "binary_real": "/usr/local/bin/php",
            "version": "8.5.11",
            "version_branch": "8.5",
            "cli_sapi": "cli",
            "zend_version": "4.5.11",
            "build_date": "Oct 21 2026 00:26:24",
            "package": {
                "manager": "none",
                "name": "",
                "version": ""
            },
            "verdict": "affected",
            "verdict_reason": "version_in_vulnerable_range",
            "confidence": "high",
            "backport": {
                "marker_state": "absent_conclusive",
                "package_changelog": ""
            },
            "sapis": {
                "available": "apache2handler",
                "active": "apache2handler",
                "mod_php": 1
            },
            "ini": {
                "session.upload_progress.enabled": {
                    "value": "1",
                    "source": "generic:/usr/local/etc/php/php.ini"
                },
                "session.upload_progress.cleanup": {
                    "value": "1",
                    "source": "generic:/usr/local/etc/php/php.ini"
                },
                "post_max_size": {
                    "value": "256M",
                    "source": "generic:/usr/local/etc/php/php.ini"
                },
                "upload_max_filesize": {
                    "value": "256M",
                    "source": "generic:/usr/local/etc/php/php.ini"
                },
                "memory_limit": {
                    "value": "32M",
                    "source": "generic:/usr/local/etc/php/php.ini"
                },
                "fatal_error_backtraces": {
                    "value": "1",
                    "source": "generic:/usr/local/etc/php/php.ini"
                },
                "session.use_only_cookies": {
                    "value": "1",
                    "source": "generic:/usr/local/etc/php/php.ini"
                },
                "session.serialize_handler": {
                    "value": "php",
                    "source": "generic:/usr/local/etc/php/php.ini"
                },
                "opcache.enable": {
                    "value": "1",
                    "source": "generic:/usr/local/etc/php/php.ini"
                }
            },
            "ini_sources": [
                {
                    "sapi": "generic",
                    "ini_file": "/usr/local/etc/php/php.ini",
                    "scan_dir": "/usr/local/etc/php/conf.d"
                }
            ],
            "tier": "red",
            "tier_label": "\u672a\u4fee",
            "tier_reason": "\u7248\u672c\u5728\u53d7\u5f71\u54cd\u533a\u95f4\u4e14\u65e0 backport \u8bc1\u636e",
            "axes": {
                "version": {
                    "state": "affected",
                    "detail": "8.5.11"
                },
                "patch_composition": {
                    "state": "unknown",
                    "detail": "\u81ea\u7f16\u8bd1\u6216\u5b98\u65b9\u955c\u50cf\uff0c\u8bfb\u4e0d\u5230\u5305\u8865\u4e01\u5217\u8868\uff0c\u5224\u4e0d\u4e86\u662f\u5426\u542b PR#22113 \u7b49\u4ef7\u4fee\u590d"
                },
                "upload_progress": {
                    "state": "enabled",
                    "detail": "session.upload_progress.enabled=1"
                },
                "lfi_exposure": {
                    "state": "sink_found",
                    "detail": "\u7ad9\u70b9\u7ea7\uff08\u5168\u90e8 webroot \u626b\u4e00\u6b21\uff09\uff1a2 \u5904\u53ef\u7591 include/\u6587\u4ef6\u8bfb\u53d6\uff08\u9759\u6001\u626b\u63cf\uff0c\u9700\u4eba\u5de5\u786e\u8ba4\u662f\u5426\u771f\u53ef\u63a7\uff09"
                },
                "serializer_reset": {
                    "state": "not_applicable",
                    "detail": "FPM \u8de8\u8bf7\u6c42\u6b8b\u7559\u72b6\u6001\uff08OOM \u8865\u4e01\u8986\u76d6\u5373\u4fee\uff09"
                },
                "fatal_error_backtraces": {
                    "state": "on",
                    "detail": "\u4ec5 8.5.x\uff1b\u987b\u4e3a 0"
                },
                "opcache": {
                    "state": "needs_patch",
                    "detail": "OPcache \u5171\u4eab\u5185\u5b58\u662f 109619 \u91cc\u5173\u4e0d\u6389\u7684\u4e00\u6761\u81c2"
                }
            },
            "notes": [
                "mod_php \u5df2\u52a0\u8f7d\uff1a\u5e94\u7528\u4ee3\u7801\u672a\u6267\u884c\u5373\u53ef\u89e6\u53d1\uff08Chain D\uff09\uff0c\u4f18\u5148\u7ea7\u6700\u9ad8"
            ],
            "findings": [
                {
                    "id": "sapi.mod_php",
                    "severity": "critical",
                    "title": "mod_php \u5df2\u52a0\u8f7d",
                    "detail": "mod_php \u4e0b OOM \u89e6\u53d1\u94fe\uff08Chain D\uff09\u5728\u5e94\u7528\u4ee3\u7801\u6267\u884c\u524d\u5b8c\u6210\uff0c\u4efb\u4f55 PHP \u7aef\u70b9\u90fd\u662f\u5165\u53e3\u3002\u8fd9\u4e00\u9879\u4f18\u5148\u7ea7\u6700\u9ad8\u3002"
                },
                {
                    "id": "ini.upload_progress_on",
                    "severity": "high",
                    "title": "session.upload_progress.enabled \u662f\u5f00\u7740\u7684",
                    "detail": "\u5f53\u524d\u503c 1\u3002\u5173\u6389\u5b83\u80fd\u780d\u6389 CVE-2026-109619 \u7684\u4f1a\u8bdd\u6ce8\u5165\u9762\uff0c\u4f46\u6321\u4e0d\u4f4f CVE-2026-109618 \u7684 OOM \u94fe\u3002"
                },
                {
                    "id": "ini.fatal_error_backtraces_on",
                    "severity": "high",
                    "title": "fatal_error_backtraces \u662f\u5f00\u7740\u7684\uff088.5 \u5206\u652f\u7279\u6709\uff09",
                    "detail": "8.5.x \u4e0a\u8fd9\u6761\u662f CVE-2026-109619 \u7684\u7b2c\u4e09\u6761\u81c2\uff08backtrace arm\uff09\u3002\u8bbe\u4e3a 0\u3002"
                },
                {
                    "id": "opcache.enabled",
                    "severity": "info",
                    "title": "OPcache \u5f00\u7740",
                    "detail": "OPcache \u5171\u4eab\u5185\u5b58\u662f CVE-2026-109619 \u91cc\u6ca1\u6709 INI \u5f00\u5173\u80fd\u5173\u6389\u7684\u4e00\u6761\u81c2\uff0c\u53ea\u80fd\u9760\u6253\u8865\u4e01\u3002"
                }
            ]
        }
    ],
    "overrides": {
        "scanned": true,
        "files": [
            {
                "file": "/var/www/html/legacy/.htaccess",
                "line": 10,
                "directive": "php_flag session.upload_progress.enabled On",
                "effect": "weakens"
            },
            {
                "file": "/var/www/html/legacy/.htaccess",
                "line": 11,
                "directive": "php_value memory_limit 64M",
                "effect": "raises"
            },
            {
                "file": "/var/www/html/legacy/.htaccess",
                "line": 12,
                "directive": "php_value post_max_size 512M",
                "effect": "raises"
            },
            {
                "file": "/var/www/html/legacy/.htaccess",
                "line": 4,
                "directive": "php_flag session.upload_progress.enabled On",
                "effect": "weakens"
            },
            {
                "file": "/var/www/html/legacy/.htaccess",
                "line": 5,
                "directive": "php_value memory_limit 64M",
                "effect": "raises"
            },
            {
                "file": "/var/www/html/legacy/.htaccess",
                "line": 6,
                "directive": "php_value post_max_size 512M",
                "effect": "raises"
            },
            {
                "file": "/var/www/html/uploads/.user.ini",
                "line": 3,
                "directive": "post_max_size = 128M",
                "effect": "raises"
            },
            {
                "file": "/var/www/html/uploads/.user.ini",
                "line": 4,
                "directive": "upload_max_filesize = 128M",
                "effect": "raises"
            }
        ]
    },
    "docker": [],
    "mitigation_impact": [
        {
            "site": "/var/www/html",
            "forms_found": 4,
            "endpoints_suspected": 0,
            "options": [
                {
                    "id": "upgrade_php",
                    "title": "\u5347\u7ea7 PHP",
                    "cost": "low",
                    "from_version": "8.5.11",
                    "to_version": "8.5.12",
                    "note": "\u5347\u7ea7\u5230\u540c\u5206\u652f\u4fee\u590d\u7248\uff1b\u4e0d\u6539\u4ee3\u7801\u3001\u4e0d\u6539\u914d\u7f6e\u3002",
                    "blocks": [],
                    "notes": [
                        "\u4e0d\u6539\u4ee3\u7801\u3001\u4e0d\u6539\u914d\u7f6e",
                        "\u552f\u4e00\u5b8c\u6574\u4fee\u590d"
                    ]
                },
                {
                    "id": "block_multipart",
                    "title": "Web \u5c42 403 multipart",
                    "cost": "high",
                    "blocks": [
                        {
                            "file": "/var/www/html/shop/admin/logo.php",
                            "line": 1,
                            "kind": "form_multipart",
                            "confidence": "high",
                            "purpose": "Logo \u4e0a\u4f20",
                            "evidence": "<form method=\"post\" enctype=\"multipart/form-data\"><input type=\"file\" name=\"logo_file\"></form>"
                        },
                        {
                            "file": "/var/www/html/shop/product-edit.php",
                            "line": 1,
                            "kind": "form_multipart",
                            "confidence": "high",
                            "purpose": "\u5546\u54c1\u56fe\u4e0a\u4f20",
                            "evidence": "<form action=\"/admin/save.php\" method=\"post\" enctype=\"multipart/form-data\">"
                        },
                        {
                            "file": "/var/www/html/blog/wp-admin-async.php",
                            "line": 1,
                            "kind": "wp_media",
                            "confidence": "high",
                            "purpose": "WordPress \u5a92\u4f53\u5e93\u4e0a\u4f20",
                            "evidence": "<script>var x = '/wp-admin/async-upload.php';</script>"
                        },
                        {
                            "file": "/var/www/html/blog/profile.php",
                            "line": 1,
                            "kind": "form_multipart",
                            "confidence": "high",
                            "purpose": "\u5934\u50cf\u4e0a\u4f20",
                            "evidence": "<form method=\"post\" enctype=\"multipart/form-data\"><input type=\"file\" name=\"avatar\"></form>"
                        }
                    ],
                    "suspected_endpoints": [],
                    "limitation": null,
                    "notes": [
                        "\u4e0d\u53d1\u8d77\u4efb\u4f55\u8bf7\u6c42\uff0c\u53ea\u8bfb\u6587\u4ef6",
                        "403 \u6389 multipart \u4f1a\u540c\u65f6\u5e9f\u6389\u5546\u54c1\u56fe/\u7ed3\u8d26\u7b49\u4e0a\u4f20"
                    ]
                },
                {
                    "id": "disable_upload_progress",
                    "title": "\u53ea\u5173 session.upload_progress",
                    "cost": "low",
                    "covers": [
                        "CVE-2026-109619 \u7684 session \u6ce8\u5165\u8def\u5f84"
                    ],
                    "does_not_cover": [
                        "CVE-2026-109618\uff08Zend \u5f15\u64ce OOM\uff0c\u4e0e upload_progress \u65e0\u5173\uff09",
                        "8.5.x \u7684 fatal_error_backtraces \u81c2\uff08\u9700\u5355\u72ec\u8bbe 0\uff09"
                    ],
                    "blocks": [],
                    "notes": [
                        "\u4e0d\u662f\u5b8c\u6574\u4fee\u590d",
                        "\u8986\u76d6\u94fe\u91cc\u7684 .htaccess / .user.ini \u53ef\u80fd\u628a\u5b83\u91cd\u65b0\u6253\u5f00"
                    ]
                }
            ]
        }
    ],
    "warnings": []
}

----------------------------------------------------------------
8. 版本判定矩阵（函数级单测）

----------------------------------------------------------------
$ bash -c 'source ../audit.sh; classify_version <ver>'
5.3.29    patched version_below_affected_range
5.4.0     affected version_in_vulnerable_range
7.4.33    affected version_in_vulnerable_range
8.1.30    affected version_in_vulnerable_range
8.2.34    affected version_in_vulnerable_range
8.2.35    patched version_at_or_above_branch_fix:8.2.35
8.3.36    patched version_at_or_above_branch_fix:8.3.36
8.4.26    affected version_in_vulnerable_range
8.4.27    patched version_at_or_above_branch_fix:8.4.27
8.5.11    affected version_in_vulnerable_range
8.5.12    patched version_at_or_above_branch_fix:8.5.12
8.6.0     unknown version_above_advisory_range:8.6.0

----------------------------------------------------------------
9. 判不了（unknown）+ 退出码 2

----------------------------------------------------------------
# 假 php 二进制报告 8.6.0 —— 在公告区间之上，工具必须拒绝猜
$ PATH=/tmp/fakephp/bin:$PATH ../audit.sh --no-docker --root /tmp/nonexistent
grep: empty (sub)expression
grep: empty (sub)expression
grep: empty (sub)expression
判不了
先看清楚下面 unknown 的原因（版本无法解析 / 二进制被 strip / patch_composition 读不到），再用包管理器版本和发行版安全公告人工确认；不要当成安全。

----------------------------------------------------------------
php-exposure-audit v0.1.0   CVE-2026-109618 / CVE-2026-109619 (CVSS 9.2)
主机 hanyuandongdeMacBook.local · Darwin 25.6.0 · 2026-10-22T09:04:15Z
----------------------------------------------------------------
PHP 安装数 : 1   未修 0 / 已修但有残留 0 / 已修且缓解到位 0 / 判不了 1
mod_php    : 未发现

--- [1/1] PHP 8.6.0   /private/tmp/fakephp/bin/php ---
结论        : 判不了
原因        : 版本无法对照公告区间
七轴检查    :
  ?? version                  unknown            8.6.0
  ?? patch_composition        unknown            自编译或官方镜像，读不到包补丁列表，判不了是否含 PR#22113 等价修复
  ok upload_progress          disabled           session.upload_progress.enabled=0
  ok lfi_exposure             no_sink_found      站点级（全部 webroot 扫一次）：静态扫描没找到，但静态扫描证不了「不存在」
  ok serializer_reset         not_applicable     FPM 跨请求残留状态（OOM 补丁覆盖即修）
  ?? fatal_error_backtraces   unknown            仅 8.5.x；须为 0
  ok opcache                  off                OPcache 共享内存是 109619 里关不掉的一条臂
版本判定    : unknown (version_above_advisory_range:8.6.0)
backport    : marker=inconclusive  changelog=未命中
SAPI        : 可用[cli]  运行中[]
构建时间    : Oct 21 2026 00:00:00
关键 ini    :
  [cli] (none)
    post_max_size                      = --             (未加载或不可用)
备注        :
  - 二进制被 strip 或读不到，patch 标记无法作为证据

--- 覆盖链 ---
未发现 .htaccess / .user.ini / php.ini 里的 PHP 指令覆盖

--- 处置选项 ---
没找到任何站点目录，三档代价都判不了。
用 --root 指定 webroot 再跑一次。

--- 说明 ---
  · 本工具只读：不写配置、不改文件、不发外部请求。
  · "不中" 只代表版本/backport 层面已修，不代表应用没有 LFI（Chain A 在已修补版本上仍可用）。
  · 缓解措施（关 upload_progress、关 backtraces）只能降风险，唯一完整修复是升级。
exit code: 2
  [PASS] unknown 退出码                              2

----------------------------------------------------------------
10. ssh 管道模式（bash -s，不需要拷贝文件）

----------------------------------------------------------------
$ cat ../audit.sh | docker exec -i pea-lab-vuln bash -s -- --no-docker | head -9
未修
把 PHP 升到 8.5.12（或同分支 8.2.35 / 8.3.36 / 8.4.27）。补丁修的是 OOM 和残留状态；upload_progress 的文件名写入是设计如此，配任何应用层 LFI 链子就通，责任在应用层。

----------------------------------------------------------------
php-exposure-audit v0.1.0   CVE-2026-109618 / CVE-2026-109619 (CVSS 9.2)
主机 1c7efd5f1be6 · Linux 6.8.0-117-generic · 2026-10-22T09:04:17Z
----------------------------------------------------------------
PHP 安装数 : 1   未修 1 / 已修但有残留 0 / 已修且缓解到位 0
mod_php    : 有（Chain D，无需应用代码即可触发）
exit code: 1
  [PASS] bash -s 管道退出码                        1

----------------------------------------------------------------
11. .audit-token 文件模式（不设环境变量，真实 HTTP）

----------------------------------------------------------------
$ docker run -d --name pea-filemode -p 18093:80 -v <tmpdir>:/var/www/html ... （不传 token 环境变量）
$ docker exec pea-filemode env | grep PHP_EXPOSURE_AUDIT_TOKEN   # 应为空
(none)
$ docker exec pea-filemode ls /var/www/html/.audit-token   # 确认不存在
  [PASS] .audit-token 不存在                         不存在
$ curl -s -o /dev/null -w "%{http_code}" -H "X-Audit-Token: $TOKEN" .../probe.php   # 还没写 .audit-token
  [PASS] 无环境变量 + 无 .audit-token → 404     404
$ docker exec pea-filemode sh -c 'printf %s $TOKEN > /var/www/html/.audit-token && chmod 644 ...'
$ curl -s -H "X-Audit-Token: $TOKEN" .../probe.php   # 只靠文件里的 token
  [PASS] 文件模式 → 200                           200
  [PASS] 文件模式 verdict                           affected
$ curl -s -o /dev/null -w "%{http_code}" -H "X-Audit-Token: wrong" .../probe.php
  [PASS] 文件模式 + 错 token → 404               404
# 收尾
  pea-filemode 已删除，临时 webroot 已清理

----------------------------------------------------------------
12. mitigation_impact — 三档处置代价（B 档只读扫表）

----------------------------------------------------------------
# 靶场里预置了 shop/admin/logo.php、shop/product-edit.php、blog/profile.php、blog/wp-admin-async.php
$ docker exec pea-lab-vuln bash /tmp/audit.sh --no-docker 2>&1 | sed -n "/处置选项/,/只关/p"
--- 处置选项（三档代价）· /var/www/html ---
A. 升级 PHP
   8.5.11 → 8.5.12
   升级到同分支修复版；不改代码、不改配置。
   代价：不改代码、不改配置。唯一完整修复。
B. Web 层 403 multipart
   代价：下面这些功能会全废（4 处）
     [high] /shop/admin/logo.php:1  Logo 上传
          <form method="post" enctype="multipart/form-data"><input type="file" name="logo_file"></form>
     [high] /shop/product-edit.php:1  商品图上传
          <form action="/admin/save.php" method="post" enctype="multipart/form-data">
     [high] /blog/wp-admin-async.php:1  WordPress 媒体库上传
          <script>var x = '/wp-admin/async-upload.php';</script>
     [high] /blog/profile.php:1  头像上传
          <form method="post" enctype="multipart/form-data"><input type="file" name="avatar"></form>
C. 只关 session.upload_progress（+ fatal_error_backtraces）

$ curl .../probe.php?format=json | jq .mitigation_impact
  site: /var/www/html | forms: 4
   high 头像上传 | blog/profile.php
   high 疑似上传（路径和字段名都看不出用途） | blog/wp-admin-async.php
   high 商品图上传 | shop/product-edit.php
   high Logo 上传 | shop/admin/logo.php
  [PASS] 三档处置齐全                             upgrade_php,block_multipart,disable_upload_progress
  [PASS] A 档给出目标版本                        8.5.12
  [PASS] B 档找到预置表单数                     4
  [PASS] C 档声明不管的事（含 109618）        2
  [PASS] B 档不误报工具自身                     0

----------------------------------------------------------------
13. 8.5.12 靶场必须如实报出 Chain A 仍为风险（不许报全绿）

----------------------------------------------------------------
# 预置了 app/view.php（间接式 LFI：$tpl = $_GET[...]; include $tpl）与 app/download.php（直接式 readfile）
download.php
view.php

$ curl :18092/probe.php?format=json   # 8.5.12，已被官方修复
tier        : orange / 已修但有残留
tier_reason : 版本已修，但站点存在 LFI 落点 —— Chain A 可打，与版本无关
  version                  patched          8.5.12
  patch_composition        pr22113_absent   8.5.12 是上游修复版，PR#22113 未合并，源码里没有 session fixation 守卫
  upload_progress          enabled          session.upload_progress.enabled=1
  lfi_exposure             sink_found       2 处可疑 include/文件读取（静态扫描，需人工确认是否真可控）
  serializer_reset         not_applicable   当前 SAPI 不是 FPM
  fatal_error_backtraces   on               fatal_error_backtraces=1（8.5.x 须为 0）
  opcache                  covered          OPcache 开着，补丁标记在
  [PASS] 8.5.12 不得判为全绿                      orange
  [PASS] patch_composition 判出无 PR#22113           pr22113_absent
  [PASS] lfi_exposure 抓到落点（含间接式）    sink_found

----------------------------------------------------------------
14. session.upload_progress 开/关对照（这一轴读的是真配置，不是硬编码）

----------------------------------------------------------------
$ docker run --name pea-upoff -p 18095:80 （只为这一行关掉 upload_progress）
$ docker exec pea-upoff php -r "echo ini_get(\"session.upload_progress.enabled\");"
  ini_get=''
  [PASS] 开了 upload_progress → enabled             enabled
  [PASS] 关了 upload_progress → disabled            disabled
# 收尾
  pea-upoff 已删除，临时 ini / webroot 已清理

----------------------------------------------------------------
15. 没有 PHP 的机器必须报「未发现 PHP」+ exit 2（假阴性回归项）

----------------------------------------------------------------
# 这里曾经是个硬伤：total=0 落进 else，被判成 patched → 输出「版本已在修复线以上」+ exit 0。
# 一个会说「你安全」的工具，在最常见的场景（扫错机器 / 容器在别的 host）里骗人。

$ docker exec pea-nophp bash /opt/pea/audit.sh --no-docker
未发现 PHP
本机未找到任何 PHP 安装。如果 PHP 跑在容器 / 另一台机器 / 非标准路径，请加 --root 或 --docker-only，或直接对那台机器跑。不要因为“没找到”就当安全。

----------------------------------------------------------------
  [PASS] 首行是「未发现 PHP」                   未发现 PHP
  [PASS] 退出码 2（不是 0）                      2
  [PASS] JSON verdict = not_applicable                  not_applicable
  [PASS] JSON targets_found = 0                         0
  [PASS] --no-docker 时提示可能漏了 docker       yes
  pea-nophp 已删除

----------------------------------------------------------------
结果: 31 PASS / 0 FAIL
```

## 这一段验证了但没写进 PASS 计数的东西

自检脚本的 31 项断言之外，下面这些是手工核过、并且直接改过代码的行为：

| 撞出来的问题 | 现象 | 修法 |
| --- | --- | --- |
| **`total=0` 报「不中」+ exit 0** | 干净机器上说「版本已在修复线以上」 | 独立 `not_applicable` 分支排在所有判定之前；exit 2 |
| **`probe.php` 空版本滑到 `patched`** | `pea_ver_num('')` = 0 < 5.4.0 → `below_affected_range` → 说安全 | `pea_version_parseable()` 前置守卫 |
| **警告抢在结论前面** | `warn()` 立刻打 stderr，合并输出时首行不是结论，破坏输出契约 | 文本模式攒着在报告末尾渲染；只有 JSON 模式走 stderr |
| **LFI 检测只抓直接式** | `$tpl = $_GET['tpl']; include $tpl;` 扫不到，把「链子还通」误报成「没找到落点」 | 加间接式：sink 用变量时回查同文件里该变量是否来自超全局 |
| **LFI 落点被数两遍** | `/var/www` 和 `/var/www/html` 各扫一次，「2 处」报成「4 处」 | 嵌套根目录去重 + 输出按 文件:行 去重 |
| **`docker run` 失败被吞掉** | 端口没从上一轮转发释放，容器起不来；输出丢进 `/dev/null`，只表现为后面 JSON 解析失败 | 保留输出并轮询等它真的能应答 200 |
| **probe 的 tier 有个死分支** | `elseif version === 'unknown'` 在已排除 unknown 的 else 里，永远为假 | 补 `not_scanned` 状态，让「LFI 没扫成」和「没找到」分开 |
| `Authorization` 头在 mod_php 下不到 `$_SERVER` | 带正确 Bearer token 仍 404 | `getallheaders()` 兜底；README 改推 `X-Audit-Token` |
| `probe.php` 权限 0600 | Apache 返回 **200** + PHP Fatal error 页 | 写进部署注意事项；自检里显式 `chmod 644` |
| `--docker-only` 报「不中」 | 容器里的 PHP 只被列出、没参与判定 | docker 结果进 `docker_verdict`，与宿主机一起取最坏值 |
| `ps \| grep php-fpm` 匹配到自己 | 把自己的命令行当成 FPM 进程 | 只读 `/proc/PID/exe`；非 Linux 用 `ps -eo comm` |
| `bash -s < audit.sh` 报 unbound variable | `set -u` 下 `BASH_SOURCE[0]` 未定义 | `${BASH_SOURCE[0]:-}` |
| 自检用固定临时目录 | 上轮残留让「本来没有 token」前提失效，测出假 PASS | `mktemp -d` + 显式断言文件不存在 |
| `opcache.enable` 空值说成「本版本无此指令」 | 5.6 有这指令，只是没编 OPcache | 区分「版本没有」和「未加载或不可用」 |
| EOL 分支建议写「升到 8.5.12 或同分支」 | 5.6 没有同分支修复版 | EOL 时改成「必须升到 8.2.35+ 之一」 |
| B 档把工具自身源码当成上传表单 | `probe.php` 里含有匹配规则本身 | 按内容标记 `php-exposure-audit` 跳过自身 |
| 同一表单被 enctype 和 file input 各数一次 | 一个 `<form>` 报两条 | 有 enctype 时只按 enctype 报 |
| 两个形态 `mitigation_impact` 形状不一致 | audit.sh 站点数组 / probe 选项数组 | probe 改成同一形状 |

## 没有验证到的

- **`lfi_exposure = not_scanned`**：只在 DOCUMENT_ROOT 不可读时触发，HTTP 场景构造不出来，只做了代码审查，没跑过真机。
- **PHP 5.4 / 5.5**：镜像源 digest 不匹配拉不下来。5.6.40 端到端通过（含 HTTP 全路径），5.4/5.5 是照同一语法约束写的，未在真机验证。
