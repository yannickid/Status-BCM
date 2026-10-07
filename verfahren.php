<?php
/**
 * Fachverfahren / Unternehmensanwendungen und externe Statusseite – nur Login Stufe 2 mit Rolle "admin".
 * Je Verfahren: Name, Kürzel, Links, Sichtbarkeit (auch je Feld extern), interne Einstufung (Kategorie, Bereich, DSB, VSA, KRITIS),
 * Unternehmen und Behörden aus dem Adressbuch, Infotexte und Alarmkreise je Rolle. Jede Änderung verlangt den TOTP-Code des Admins und wird im Audit-Log protokolliert.
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
    page_start('Fachverfahren');
    nav('verfahren');
    echo '<div class="alert alert-warning">Die Pflege der Fachverfahren ist Admins vorbehalten.</div>';
    page_end();
    exit;
}

$errors = [];
$old = [];
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    csrf_verify();
    $act = (string)($_POST['action'] ?? '');
    $how = ['totp' => true];
    if (!in_array($act, ['app_save', 'app_delete', 'public_page'], true)) {
        $errors[] = 'Ungültige Aktion.';
    } elseif ($err = admin_totp_check($user, 'apps', $act)) {
        $errors[] = $err;
    } else {
        $id = (string)($_POST['id'] ?? '');
        $err = match ($act) {
            'app_save' => app_save($id, $_POST, $user['id'], $how),
            'app_delete' => app_delete($id, $user['id'], $how),
            'public_page' => public_page_set($_POST, $user['id'], $how),
        };
        if ($err) {
            $errors[] = $err;
        } else {
            flash('ok', ['app_save' => 'Fachverfahren gespeichert.', 'app_delete' => 'Fachverfahren gelöscht.', 'public_page' => 'Externe Statusseite gespeichert.'][$act]);
            redirect('verfahren.php');
        }
    }
    $old = $_POST;
}

/** Formularfelder eines Fachverfahrens ($a = gespeicherte Werte oder Eingaben nach Fehler). */
function app_fields(array $a, string $sfx): string
{
    $v = fn(string $k) => h((string)($a[$k] ?? ''));
    $cb = fn(string $k, string $label, string $hint = '') => '<div class="form-check"><input class="form-check-input" type="checkbox" name="' . $k . '" value="1" id="' . $k . $sfx . '"'
        . (!empty($a[$k]) ? ' checked' : '') . '><label class="form-check-label" for="' . $k . $sfx . '">' . $label
        . ($hint !== '' ? ' <span class="text-body-secondary small">(' . $hint . ')</span>' : '') . '</label></div>';
    $in = fn(string $k, string $label, int $max, string $type = 'text', string $hint = '') => '<label class="form-label small" for="' . $k . $sfx . '">' . $label
        . ($hint !== '' ? ' <span class="text-body-secondary">(' . $hint . ')</span>' : '') . '</label>'
        . '<input class="form-control mb-2" id="' . $k . $sfx . '" type="' . $type . '" name="' . $k . '" maxlength="' . $max . '" value="' . $v($k) . '">';
    $o = $in('name', 'Name', 80) . $in('short', 'Kürzel', 16, 'text', 'optional, z. B. "eAkte"')
        . $in('login_url', 'Link zur Anmeldung', 300, 'url', 'https://…, optional') . $in('help_url', 'Link zu Doku, Hilfe, Support', 300, 'url', 'https://…, optional');
    $o .= '<fieldset class="mb-2"><legend class="small fw-semibold mb-1">Sichtbarkeit</legend>'
        . $cb('green_int', 'Intern auch "Verfügbar" anzeigen', 'sonst nur bei Einschränkung')
        . $cb('external', 'Auf der externen Statusseite zeigen', 'ohne Login, nur allgemeine Texte')
        . $cb('green_ext', 'Extern auch "Verfügbar" anzeigen') . '</fieldset>'
        . '<fieldset class="mb-2"><legend class="small fw-semibold mb-1">Extern sichtbar</legend><div class="d-flex flex-wrap gap-3">';
    foreach (SBCM_APP_EXT as $k => $label) {
        $o .= $cb($k, $label);
    }
    $o .= '</div><p class="small text-body-secondary mb-0">Name oder Kürzel muss extern sichtbar sein.</p></fieldset>';
    $o .= '<fieldset class="mb-2 border rounded p-2"><legend class="small fw-semibold mb-1 float-none w-auto px-1">Nur intern (nie extern)</legend>'
        . $in('category', 'Kategorie', 60) . $in('area', 'Bereich', 60)
        . '<label class="form-label small" for="dsb' . $sfx . '">Datenschutz: Sensibilität der Daten (DSB)</label><select class="form-select mb-2" id="dsb' . $sfx . '" name="dsb">';
    foreach (SBCM_APP_DSB as $k => $label) {
        $o .= '<option value="' . h($k) . '"' . ((string)($a['dsb'] ?? '') === $k ? ' selected' : '') . '>' . h($label) . '</option>';
    }
    $o .= '</select>' . $cb('vsa', 'VSA (Verschlusssachen)') . $cb('kritis', 'KRITIS (kritische Infrastruktur)')
        . '<p class="small text-body-secondary mb-0">Kategorie und Bereich sehen alle Angemeldeten. DSB, VSA, KRITIS sowie Unternehmen und Behörden '
        . 'sehen nur Personen mit persönlicher Kennung.</p></fieldset>';
    $orgs = orgs_all();
    $sel = array_map('strval', (array)($a['orgs'] ?? []));
    $o .= '<fieldset class="mb-2 border rounded p-2"><legend class="small fw-semibold mb-1 float-none w-auto px-1">Unternehmen und Behörden informieren</legend>';
    if (!$orgs) {
        $o .= '<p class="small text-body-secondary mb-0">Noch keine Einträge. Bitte zuerst unter <a href="system.php#adressbuch">System</a> im Adressbuch anlegen.</p>';
    }
    foreach ($orgs as $i => $org) {
        $id = 'o' . $sfx . '_' . (int)$i;
        $o .= '<div class="form-check"><input class="form-check-input" type="checkbox" name="orgs[]" value="' . h($org['id']) . '" id="' . $id . '"'
            . (in_array($org['id'], $sel, true) ? ' checked' : '') . '><label class="form-check-label" for="' . $id . '">' . h($org['name'])
            . ' <span class="text-body-secondary small">(' . count($org['emails']) . ' Adr.)</span></label></div>';
    }
    $o .= '<p class="small text-body-secondary mb-0">Sie erhalten bei jeder Meldung zu diesem Verfahren automatisch die allgemeine Fassung (keine Übungen).</p></fieldset>';
    $ta = fn(string $k, string $label, string $hint) => '<label class="form-label small" for="' . $k . $sfx . '">' . $label
        . ' <span class="text-body-secondary">(' . $hint . ')</span></label><textarea class="form-control mb-2" id="' . $k . $sfx . '" name="' . $k
        . '" rows="2" maxlength="600">' . $v($k) . '</textarea>';
    $o .= '<fieldset class="mb-2 border rounded p-2"><legend class="small fw-semibold mb-1 float-none w-auto px-1">Infotexte für dieses Verfahren</legend>'
        . $ta('text_nutzende', 'Infotext für Nutzende', 'optional; leer = Text aus System')
        . $ta('text_extern', 'Infotext für Unternehmen und Behörden', 'optional; leer = Text aus System') . '</fieldset>';
    $circles = alarm_circles();
    $o .= '<fieldset class="mb-2 border rounded p-2"><legend class="small fw-semibold mb-1 float-none w-auto px-1">Alarmkreise je Rolle</legend>';
    if (!$circles) {
        $o .= '<p class="small text-body-secondary mb-0">Noch keine Alarmkreise. Bitte zuerst unter <a href="system.php">System</a> anlegen.</p>';
    }
    foreach ($circles ? SBCM_APP_ROLES : [] as $r => $label) {
        $sel = array_map('strval', (array)($a['roles'][$r] ?? []));
        $o .= '<fieldset class="mb-1"><legend class="small mb-0">' . h($label) . '</legend><div class="d-flex flex-wrap gap-3">';
        foreach ($circles as $i => $c) {
            $id = 'r' . $sfx . $r . (int)$i;
            $o .= '<div class="form-check"><input class="form-check-input" type="checkbox" name="roles[' . $r . '][]" value="' . h($c['id']) . '" id="' . $id . '"'
                . (in_array($c['id'], $sel, true) ? ' checked' : '') . '><label class="form-check-label small" for="' . $id . '">' . h($c['name']) . '</label></div>';
        }
        $o .= '</div></fieldset>';
    }
    $o .= '<p class="small text-body-secondary mb-0">Die Kreise bringen E-Mail, Signal und GroupAlarm mit (Pflege unter System). '
        . 'Bei jeder Meldung erhalten sie automatisch eine E-Mail; Signal und GroupAlarm nur mit ALARM.</p></fieldset>';
    return $o;
}

page_start('Fachverfahren');
nav('verfahren');
echo '<h1 class="h4 mb-3">Fachverfahren</h1>';
render_flash();
foreach ($errors as $e) {
    echo '<div class="alert alert-danger" role="alert">' . h($e) . '</div>';
}
$oldAct = (string)($old['action'] ?? '');
$oldId = (string)($old['id'] ?? '');

/* Liste */
$apps = apps_all();
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Fachverfahren (' . count($apps) . ')</h2>';
if (!$apps) {
    echo '<p class="small text-body-secondary mb-0">Noch keine Fachverfahren angelegt.</p>';
}
foreach ($apps as $i => $a) {
    $sfx = 'a' . (int)$i;
    $vals = $oldAct === 'app_save' && $oldId === $a['id'] ? $old : $a;
    $tags = array_filter([$a['external'] ? 'extern sichtbar' : 'nur intern', $a['short']]);
    echo '<details class="border-bottom py-2"' . ($oldId === $a['id'] ? ' open' : '') . '><summary><strong>' . h($a['name']) . '</strong> <span class="small text-body-secondary">('
        . h(implode(' · ', $tags)) . ')</span></summary>';
    echo '<form method="post" action="verfahren.php" class="mt-2" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="app_save">'
        . '<input type="hidden" name="id" value="' . h($a['id']) . '">' . app_fields($vals, $sfx) . totp_input('s' . $sfx)
        . '<button class="btn btn-sm btn-primary" type="submit">Speichern</button></form>';
    echo '<form method="post" action="verfahren.php" class="mt-2" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="app_delete">'
        . '<input type="hidden" name="id" value="' . h($a['id']) . '"><details><summary class="small text-danger">Löschen</summary>'
        . '<p class="small mb-1">Bestehende Meldungen behalten den Namen des Verfahrens.</p>' . totp_input('d' . $sfx)
        . '<button class="btn btn-sm btn-outline-danger" type="submit">Fachverfahren löschen</button></details></form>';
    echo '</details>';
}
echo '</div></div>';

/* Neu */
$vals = $oldAct === 'app_save' && $oldId === '' ? $old : ['green_int' => '1', 'ext_name' => '1'];
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Neues Fachverfahren</h2>';
echo '<form method="post" action="verfahren.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="app_save"><input type="hidden" name="id" value="">'
    . app_fields($vals, 'new') . totp_input('new') . '<button class="btn btn-primary" type="submit">Anlegen</button></form></div></div>';

/* Externe Statusseite */
$pp = $oldAct === 'public_page' ? public_page_set_values($old) : public_page();
$url = rtrim((string)cfg('app.base_url'), '/') . '/extern.php';
echo '<div class="card shadow-sm mb-3" id="extern"><div class="card-body"><h2 class="h5">Externe Statusseite (ohne Login)</h2>';
echo '<p class="small">Zeigt nur Fachverfahren mit "extern sichtbar", nur mit Einschränkung (oder "Verfügbar", wo gewählt), mit der allgemeinen Textfassung '
    . 'und ohne interne Angaben. Telefon und E-Mail erscheinen erst nach einem Klick auf "Kontakt anzeigen" und stehen nicht im Seitenquelltext. '
    . 'Suchmaschinen werden ausgesperrt (noindex, robots.txt). Adresse: <span class="font-monospace break-all">' . h($url) . '</span></p>';
$f = fn(string $k, string $label, int $max, string $type = 'text') => '<label class="form-label small" for="pp' . $k . '">' . $label . '</label>'
    . '<input class="form-control mb-2" id="pp' . $k . '" type="' . $type . '" name="' . $k . '" maxlength="' . $max . '" value="' . h((string)$pp[$k]) . '">';
echo '<form method="post" action="verfahren.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="public_page">'
    . '<div class="form-check mb-2"><input class="form-check-input" type="checkbox" name="enabled" value="1" id="ppenabled"' . ($pp['enabled'] ? ' checked' : '') . '>'
    . '<label class="form-check-label" for="ppenabled"><strong>Externe Seite einschalten</strong></label></div>'
    . $f('title', 'Titel', 80) . $f('intro', 'Einleitung (optional)', 300) . $f('phone', 'Rufnummer (optional)', 40, 'tel')
    . $f('email', 'E-Mail (optional)', 120, 'email') . $f('ticket_url', 'Link zum Ticketsystem (optional, https://…)', 300, 'url')
    . $f('ticket_label', 'Bezeichnung des Links', 40) . $f('hours', 'Erreichbarkeit (optional, z. B. "Mo–Fr 7–18 Uhr")', 120)
    . totp_input('pp') . '<button class="btn btn-primary" type="submit">Speichern</button></form></div></div>';
page_end();

/** Eingaben nach einem Fehler wieder anzeigen. */
function public_page_set_values(array $in): array
{
    $p = public_page();
    foreach ($p as $k => $v) {
        $p[$k] = $k === 'enabled' ? !empty($in['enabled']) : (string)($in[$k] ?? '');
    }
    return $p;
}
