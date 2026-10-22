<?php
// 靶场首页 —— 一个普通应用页面，用来证明 mod_php 真的在跑
echo "lab ok\n";
echo "PHP " . PHP_VERSION . "\n";
echo "SAPI " . php_sapi_name() . "\n";
echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n";
