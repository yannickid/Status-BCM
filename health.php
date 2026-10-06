<?php
/**
 * Gesundheitsprüfung für externe Uptime-Dienste (z. B. UptimeRobot, Uptime Kuma, Hoster-Monitoring).
 * Antwort 200 "ok" oder 503 mit kurzem Grund ("db", "cron"). Verrät keine Inhalte.
 * Optional monitor.health_token: dann nur mit ?t=<token> bzw. Header X-Health-Token (sonst 403).
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';

ini_set('display_errors', '0');
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
header('X-Robots-Tag: noindex, nofollow');
header('X-Content-Type-Options: nosniff');

$token = (string)cfg('monitor.health_token', '');
if ($token !== '' && !hash_equals($token, (string)($_SERVER['HTTP_X_HEALTH_TOKEN'] ?? ($_GET['t'] ?? '')))) {
    http_response_code(403);
    exit("forbidden\n");
}
try {
    db()->query('SELECT 1')->fetchColumn();
} catch (Throwable $e) {
    error_log('Status-BCM health: ' . $e->getMessage());
    http_response_code(503);
    exit("db\n");
}
if (cron_age_minutes() === null || cron_stale()) {
    http_response_code(503);
    exit("cron\n");
}
echo "ok\n";
