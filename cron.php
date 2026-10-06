<?php
/**
 * Cron: Erinnerungen bei abgelaufener Gültigkeit (Autor + cc_default_mail1), optionale
 * Auto-Rücksetzung, täglicher Audit-Anker, Aufräumen.
 *
 * Aufruf:  php cron.php            (CLI, empfohlen: alle 5 Minuten)
 *     oder GET /cron.php?t=<cron.token>   bzw. Header "X-Cron-Token: <token>" (Webspace-Cron/URL-Dienst)
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
date_default_timezone_set('UTC');
mb_internal_encoding('UTF-8');

$cli = PHP_SAPI === 'cli';
if (!$cli) {
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Robots-Tag: noindex, nofollow');
    $token = (string)cfg('cron.token', '');
    $given = (string)($_SERVER['HTTP_X_CRON_TOKEN'] ?? ($_GET['t'] ?? ''));
    $allow = (array)cfg('cron.ip_allowlist', []);
    try {
        if ($token === '' || throttle_locked('cron') > 0) {
            http_response_code(403);
            exit("forbidden\n");
        }
        if (!hash_equals($token, $given) || ($allow && !in_array(client_ip(), $allow, true))) {
            throttle_record('cron', null, false);
            fail_delay();
            http_response_code(403);
            exit("forbidden\n");
        }
    } catch (Throwable $e) {
        error_log('Status-BCM cron: ' . $e->getMessage());
        http_response_code(500);
        exit("error\n");
    }
}

$lock = @fopen(storage_dir() . '/cron.lock', 'c');
if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
    echo "busy\n";
    exit(0);
}

try {
    $log = run_cron();
    echo $cli ? implode("\n", $log) . ($log ? "\n" : "") . "ok\n" : "ok\n";
} catch (Throwable $e) {
    error_log('Status-BCM cron: ' . $e->getMessage());
    http_response_code(500);
    echo "error\n";
    exit(1);
} finally {
    flock($lock, LOCK_UN);
    fclose($lock);
}
