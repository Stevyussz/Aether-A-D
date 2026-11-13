<?php
$nonce = (string)($_GET['nonce'] ?? '');
$type = (string)($_GET['type'] ?? 'root');

if ($nonce === '' || strlen($nonce) > 64 || !ctype_alnum($nonce)) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    die("invalid nonce\n");
}

if ($type !== 'user' && $type !== 'root') {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    die("invalid type\n");
}

$key_dir = getenv('PORTAL_KEY_DIR') ?: '/var/lib/portal';
$key_file = $key_dir . '/proof_' . $type . '_key';

$key = '';
if (is_readable($key_file)) {
    $key = trim((string)@file_get_contents($key_file));
}

if (strlen($key) !== 64 || !ctype_alnum($key)) {
    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    die("flag verification unavailable\n");
}

header('Content-Type: text/plain; charset=utf-8');
echo hash_hmac('sha256', $nonce, $key) . "\n";