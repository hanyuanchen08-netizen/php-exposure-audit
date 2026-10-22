<?php
// 典型的 Chain A 落点：用户可控的文件名直接进 include
$tpl = $_GET['tpl'];
include $tpl . '.php';
