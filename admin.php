<?php
/**
 * Benutzerverwaltung – nur Login Stufe 2 mit Rolle "admin".
 * Jede Änderung verlangt den TOTP-Code des Admins und wird im Audit-Log protokolliert.
 * Benutzer werden nie gelöscht, nur deaktiviert (Nachvollziehbarkeit im Protokoll).
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';
bootstrap();

if (!stage1_ok()) {
    redirect('index.php');
}
$user = stage2_user();
if (!$user || user_needs_setup($user)) {
    redirect('change.php');
}
if ($user['role'] !== 'admin') {
    http_response_code(403);
    page_start('Benutzer');
    nav('admin');
    echo '<div class="alert alert-warning">Die Benutzerverwaltung ist Admins vorbehalten.</div>';
    page_end();
    exit;
}

$errors = [];
$old = [];
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    csrf_verify();
    $act = (string)($_POST['action'] ?? '');
    $target = strtolower(trim((string)($_POST['id'] ?? '')));
    $allowed = ['create', 'reset_pw', 'reset_totp', 'disable', 'enable', 'role'];
    if (!in_array($act, $allowed, true)) {
        $errors[] = 'Ungültige Aktion.';
    } elseif ($err = admin_totp_check($user, 'user:' . $target, $act)) {
        $errors[] = $err;
    } else {
        try {
            $once = account_action($act, $target, [
                'name' => (string)($_POST['name'] ?? ''), 'email' => (string)($_POST['email'] ?? ''),
                'role' => (string)($_POST['role'] ?? 'editor'),
            ], $user['id'], ['totp' => true]);
            $msg = [
                'create' => 'Benutzer angelegt.', 'reset_pw' => 'Passwort zurückgesetzt.', 'reset_totp' => 'TOTP zurückgesetzt – die App wird beim nächsten Login neu gekoppelt.',
                'disable' => 'Benutzer deaktiviert.', 'enable' => 'Benutzer aktiviert.', 'role' => 'Rolle geändert.',
            ][$act];
            flash('ok', $target . ': ' . $msg);
            if ($once !== null) {
                flash('info', 'Einmalpasswort für ' . $target . ': ' . $once . ' – nur jetzt sichtbar. Bitte persönlich oder telefonisch übergeben, '
                    . 'nicht per E-Mail. Beim ersten Login werden ein eigenes Passwort und die Authenticator-App eingerichtet.');
            }
            redirect('admin.php');
        } catch (InvalidArgumentException $e) {
            $errors[] = $e->getMessage();
            $old = $_POST;
        }
    }
}

function action_form(string $id, string $action, string $label, string $btn, string $extra = ''): string
{
    $sfx = $action . '-' . $id;
    return '<form method="post" action="admin.php" class="border rounded p-2 mb-2" autocomplete="off">' . csrf_field()
        . '<input type="hidden" name="action" value="' . h($action) . '"><input type="hidden" name="id" value="' . h($id) . '">'
        . '<div class="fw-semibold small mb-1">' . h($label) . '</div>' . $extra . totp_input($sfx)
        . '<button class="btn btn-sm ' . $btn . '" type="submit">' . h($label) . '</button></form>';
}

$all = users(true);
$lastLogin = [];
$q = db()->prepare('SELECT ts FROM ' . t('audit') . ' WHERE action = ? AND actor = ? ORDER BY seq DESC LIMIT 1');
foreach (array_keys($all) as $id) {
    $q->execute(['login2.ok', $id]);
    $lastLogin[$id] = $q->fetchColumn() ?: null;
}
$maxAge = (int)cfg('auth.password_max_age_days', 0);

page_start('Benutzer');
nav('admin');
echo '<h1 class="h4 mb-3">Benutzerverwaltung</h1>';
render_flash();
foreach ($errors as $e) {
    echo '<div class="alert alert-danger" role="alert">' . h($e) . '</div>';
}

/* Richtlinie und Stufe-1-Passwort */
$s1set = stage1_set_at();
$s1max = (int)cfg('auth.stage1_max_age_days', 0);
echo '<div class="card shadow-sm mb-3"><div class="card-body small">';
echo '<div><strong>Passwort-Gültigkeit Stufe 2:</strong> ' . ($maxAge > 0 ? $maxAge . ' Tage, Erinnerung ' . (int)cfg('auth.password_remind_days', 14)
    . ' Tage vorher per E-Mail (Benutzer + cc_default_mail1)' : 'unbefristet (Wechsel nur anlassbezogen)') . '</div>';
echo '<div><strong>Zugangspasswort Stufe 1:</strong> gesetzt ' . h($s1set !== '' ? fmt_local($s1set) : 'unbekannt (vor Version mit Datum)')
    . ($s1max > 0 && $s1set !== '' ? ' · Wechsel empfohlen bis ' . h(fmt_local(gmdate('Y-m-d H:i:s', utc_ts($s1set) + $s1max * 86400))) : '')
    . ' · Änderung unter <a href="system.php">System</a></div>';
echo '</div></div>';

/* Benutzerliste */
$badge = ['ok' => ['success', 'gültig'], 'soon' => ['warning', 'läuft bald ab'], 'expired' => ['danger', 'abgelaufen'], 'none' => ['secondary', 'unbefristet']];
echo '<h2 class="h5">Benutzer (' . count($all) . ')</h2><div class="list-group mb-3">';
foreach ($all as $id => $u) {
    [$bc, $bt] = $badge[pw_state($u)];
    echo '<div class="list-group-item">';
    echo '<div class="d-flex flex-wrap justify-content-between gap-1"><strong>' . h($u['name']) . ' <span class="text-body-secondary fw-normal">(' . h($id) . ')</span></strong>'
        . '<span>' . ($u['role'] === 'admin' ? '<span class="badge text-bg-dark">Admin</span> ' : '<span class="badge text-bg-light border">Redaktion</span> ')
        . ($u['active'] ? '' : '<span class="badge text-bg-secondary">deaktiviert</span> ')
        . ($u['mac_ok'] ? '' : '<span class="badge text-bg-danger">Integritätsfehler</span> ')
        . '<span class="badge text-bg-' . $bc . '">' . h($bt) . '</span></span></div>';
    echo '<div class="small text-body-secondary">' . h($u['email'] !== '' ? mask_email($u['email']) : '–')
        . ' · TOTP: ' . ($u['totp_secret'] !== '' ? 'ja' : 'noch nicht gekoppelt')
        . ($u['must_change'] ? ' · Einmalpasswort offen' : '') . '</div>';
    echo '<div class="small text-body-secondary">Passwort gesetzt: ' . h(fmt_local($u['pw_set_at'] ?? null))
        . ' · gültig bis: ' . h(empty($u['pw_valid_until']) ? 'unbefristet' : fmt_local($u['pw_valid_until']))
        . ' · letzte Anmeldung: ' . h(fmt_local($lastLogin[$id] ?? null)) . '</div>';
    if ($u['source'] === 'config') {
        echo '<div class="small mt-1">Steht in config.local.inc.php (älterer Weg) – Änderung nur dort bzw. per <code>php setup.php migrate-users</code>.</div>';
    } else {
        echo '<details class="mt-2"><summary class="small">Aktionen</summary><div class="mt-2">';
        echo action_form($id, 'reset_pw', 'Passwort zurücksetzen (Einmalpasswort)', 'btn-outline-primary');
        echo action_form($id, 'reset_totp', 'Authenticator-App neu koppeln', 'btn-outline-primary');
        $sel = '<select class="form-select form-select-sm mb-2" name="role" aria-label="Rolle">'
            . '<option value="editor"' . ($u['role'] === 'editor' ? ' selected' : '') . '>Redaktion (Status setzen)</option>'
            . '<option value="admin"' . ($u['role'] === 'admin' ? ' selected' : '') . '>Admin (zusätzlich Benutzerverwaltung)</option></select>';
        echo action_form($id, 'role', 'Rolle ändern', 'btn-outline-secondary', $sel);
        echo $u['active'] ? action_form($id, 'disable', 'Deaktivieren', 'btn-outline-danger') : action_form($id, 'enable', 'Aktivieren', 'btn-outline-success');
        echo '</div></details>';
    }
    echo '</div>';
}
echo '</div>';

/* Neuer Benutzer */
$o = fn(string $k) => h((string)($old[$k] ?? ''));
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Neuen Benutzer anlegen</h2>';
echo '<p class="small text-body-secondary">Es wird ein Einmalpasswort erzeugt und einmalig angezeigt. Beim ersten Login legt die Person ein eigenes Passwort fest und koppelt ihre Authenticator-App.</p>';
echo '<form method="post" action="admin.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="create">';
echo '<label class="form-label" for="nid">Benutzerkennung</label><input class="form-control mb-2" id="nid" name="id" pattern="[a-z0-9_\-]{2,32}" maxlength="32" autocapitalize="none" required value="' . $o('id') . '">';
echo '<label class="form-label" for="nname">Name</label><input class="form-control mb-2" id="nname" name="name" maxlength="100" required value="' . $o('name') . '">';
echo '<label class="form-label" for="nmail">E-Mail (für Erinnerungen)</label><input class="form-control mb-2" id="nmail" type="email" name="email" required value="' . $o('email') . '">';
echo '<label class="form-label" for="nrole">Rolle</label><select class="form-select mb-2" id="nrole" name="role"><option value="editor">Redaktion (Status setzen)</option><option value="admin">Admin (zusätzlich Benutzerverwaltung)</option></select>';
echo totp_input('new');
echo '<div class="d-grid d-sm-block"><button class="btn btn-primary" type="submit">Anlegen</button></div></form></div></div>';
page_end();
