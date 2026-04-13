<?php
// Email Solutions

/**
 * Email Solutions (canonical name: "Email Solutions")
 *
 * Root-only WHM (cPanel) + CWP plugin for outbound mail sanity checks.
 *
 * Version: 0.0.2
 *
 * Inspired by cPanel Tech MSP (msp.pl): https://github.com/CpanelInc/tech-MSP
 */

declare(strict_types=1);

// Polyfill for PHP 7
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool
    {
        return $needle === '' || strpos($haystack, $needle) === 0;
    }
}

// ==========================
// 1) Environment Detection
// ==========================

$isCPanelServer = (
    (is_dir('/usr/local/cpanel') || is_dir('/var/cpanel') || is_dir('/etc/cpanel')) &&
    (is_file('/usr/local/cpanel/cpanel') || is_file('/usr/local/cpanel/version'))
);

$isCWPServer = is_dir('/usr/local/cwp');

if ($isCPanelServer) {
    if (getenv('REMOTE_USER') !== 'root') {
        exit('Access Denied');
    }

    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
} elseif ($isCWPServer) {
    // CWP session model
    if (!isset($_SESSION['logged']) || $_SESSION['logged'] != 1 || !isset($_SESSION['username']) || $_SESSION['username'] !== 'root') {
        exit('Access Denied');
    }
} else {
    // Unknown platform; allow limited display for testing.
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

// ==========================
// 2) CSRF / Helpers
// ==========================

$CSRF_TOKEN = null;
if (!isset($_SESSION['csrf_token'])) {
    $CSRF_TOKEN = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $CSRF_TOKEN;
} else {
    $CSRF_TOKEN = (string)$_SESSION['csrf_token'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token'], $_SESSION['csrf_token']) || !hash_equals((string)$_SESSION['csrf_token'], (string)$_POST['csrf_token'])) {
        exit('Invalid CSRF token');
    }
}

function imh_read_file(string $path, int $maxBytes = 1048576): string
{
    if (!is_file($path) || !is_readable($path)) return '';

    // Support gzipped logs when possible.
    if (preg_match('/\.gz$/', $path) && function_exists('gzopen')) {
        $fh = @gzopen($path, 'rb');
        if ($fh === false) return '';
        $buf = '';
        while (!gzeof($fh) && strlen($buf) < $maxBytes) {
            $chunk = @gzread($fh, min(65536, $maxBytes - strlen($buf)));
            if (!is_string($chunk) || $chunk === '') break;
            $buf .= $chunk;
        }
        @gzclose($fh);
        return $buf;
    }

    $data = @file_get_contents($path, false, null, 0, $maxBytes);
    return is_string($data) ? $data : '';
}

function imh_read_file_lines(string $path, int $maxBytes = 1048576): array
{
    $data = imh_read_file($path, $maxBytes);
    if ($data === '') return [];
    $lines = preg_split('/\r\n|\r|\n/', $data);
    return is_array($lines) ? $lines : [];
}

function imh_parse_kv_map_file(string $path): array
{
    // Parses files like /etc/mailips and /etc/mailhelo
    // Format: key: value
    // Comments (#) and blank lines ignored.

    $out = [];
    foreach (imh_read_file_lines($path) as $line) {
        $line = trim((string)$line);
        if ($line === '' || str_starts_with($line, '#')) continue;

        // Strip trailing comments after some whitespace
        $line2 = preg_replace('/\s+#.*$/', '', $line);
        if (!is_string($line2)) continue;

        $parts = explode(':', $line2, 2);
        if (count($parts) !== 2) continue;

        $k = strtolower(trim($parts[0]));
        $v = trim($parts[1]);
        if ($k === '' || $v === '') continue;

        $out[$k] = $v;
    }
    return $out;
}

function imh_parse_simple_kv_file(string $path): array
{
    // Parses key=value files (e.g. /var/cpanel/cpanel.config, /etc/exim.conf.localopts)
    $out = [];
    foreach (imh_read_file_lines($path) as $line) {
        $line = trim((string)$line);
        if ($line === '' || str_starts_with($line, '#')) continue;
        $parts = explode('=', $line, 2);
        if (count($parts) !== 2) continue;
        $k = trim($parts[0]);
        $v = trim($parts[1]);
        if ($k === '') continue;
        $out[$k] = $v;
    }
    return $out;
}

function imh_split_ip_list(string $raw): array
{
    // cPanel uses semicolons for multiple IPs.
    $raw = trim($raw);
    if ($raw === '') return [];
    $parts = preg_split('/\s*;\s*/', $raw);
    if (!is_array($parts)) return [];
    $ips = [];
    foreach ($parts as $p) {
        $p = trim((string)$p);
        if ($p === '') continue;
        $ips[] = $p;
    }
    $ips = array_values(array_unique($ips));
    return $ips;
}

function imh_dns_get_a_aaaa(string $host): array
{
    $host = trim($host);
    if ($host === '') return [];

    $records = @dns_get_record($host, DNS_A + DNS_AAAA);
    if (!is_array($records)) return [];

    $ips = [];
    foreach ($records as $r) {
        if (isset($r['ip']) && is_string($r['ip'])) $ips[] = $r['ip'];
        if (isset($r['ipv6']) && is_string($r['ipv6'])) $ips[] = $r['ipv6'];
    }

    $ips = array_values(array_unique(array_filter($ips)));
    return $ips;
}

function imh_dns_ptr(string $ip): string
{
    $ip = trim($ip);
    if ($ip === '') return '';
    $ptr = @gethostbyaddr($ip);
    if (!is_string($ptr) || $ptr === $ip) return '';
    return rtrim($ptr, '.');
}

function imh_rbl_lookup(string $ip, string $rbl): bool
{
    // True = listed
    $ip = trim($ip);
    $rbl = trim($rbl);
    if ($ip === '' || $rbl === '') return false;

    $parts = explode('.', $ip);
    if (count($parts) !== 4) return false;

    $rev = implode('.', array_reverse($parts));
    $q = $rev . '.' . $rbl;
    $a = @dns_get_record($q, DNS_A);
    if (!is_array($a) || count($a) === 0) return false;

    foreach ($a as $rr) {
        if (isset($rr['ip']) && is_string($rr['ip']) && preg_match('/^127\\.0\\.0\\./', $rr['ip'])) {
            return true;
        }
    }

    return false;
}

function imh_html_badge(bool $ok, string $okText = 'OK', string $badText = 'Check'): string
{
    $cls = $ok ? 'imh-badge imh-badge-ok' : 'imh-badge imh-badge-bad';
    $txt = $ok ? $okText : $badText;
    return '<span class="' . $cls . '">' . htmlspecialchars($txt) . '</span>';
}

function imh_top_counts(array $items, int $limit, int $threshold): array
{
    $counts = [];
    foreach ($items as $it) {
        $it = (string)$it;
        if ($it === '') continue;
        $counts[$it] = ($counts[$it] ?? 0) + 1;
    }

    // Filter threshold
    foreach ($counts as $k => $v) {
        if ($v < $threshold) unset($counts[$k]);
    }

    arsort($counts);
    if ($limit > 0) {
        $counts = array_slice($counts, 0, $limit, true);
    }

    return $counts;
}

function imh_get_all_outbound_ips_cpanel(): array
{
    $ips = [];

    // Primary IP
    $mainip = trim(imh_read_file('/var/cpanel/mainip', 1024));
    if ($mainip !== '' && preg_match('/^\d+\.\d+\.\d+\.\d+$/', $mainip)) {
        $ips[] = $mainip;
    }

    // /etc/mailips IPs (may include semicolon lists)
    $mailips = imh_parse_kv_map_file('/etc/mailips');
    foreach ($mailips as $domain => $ipRaw) {
        foreach (imh_split_ip_list((string)$ipRaw) as $ip) {
            if (preg_match('/^\d+\.\d+\.\d+\.\d+$/', $ip)) $ips[] = $ip;
        }
    }

    $ips = array_values(array_unique($ips));
    sort($ips);
    return $ips;
}

// ==========================
// 3) Inputs
// ==========================

$auth_limit = isset($_POST['auth_limit']) ? (int)$_POST['auth_limit'] : 10;
$auth_threshold = isset($_POST['auth_threshold']) ? (int)$_POST['auth_threshold'] : 1;
$auth_max_bytes = isset($_POST['auth_max_bytes']) ? (int)$_POST['auth_max_bytes'] : 2097152; // 2MB

if ($auth_limit < 0) $auth_limit = 10;
if ($auth_threshold < 1) $auth_threshold = 1;
if ($auth_max_bytes < 65536) $auth_max_bytes = 65536;
if ($auth_max_bytes > 10485760) $auth_max_bytes = 10485760;

$maillog_limit = isset($_POST['maillog_limit']) ? (int)$_POST['maillog_limit'] : 20;
$maillog_threshold = isset($_POST['maillog_threshold']) ? (int)$_POST['maillog_threshold'] : 1;
$maillog_max_bytes = isset($_POST['maillog_max_bytes']) ? (int)$_POST['maillog_max_bytes'] : 2097152; // 2MB
$maillog_rotated = isset($_POST['maillog_rotated']) && (string)$_POST['maillog_rotated'] === '1';

if ($maillog_limit < 0) $maillog_limit = 20;
if ($maillog_threshold < 1) $maillog_threshold = 1;
if ($maillog_max_bytes < 65536) $maillog_max_bytes = 65536;
if ($maillog_max_bytes > 10485760) $maillog_max_bytes = 10485760;

$rbl_default = [
    'b.barracudacentral.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'ips.backscatterer.org',
    'zen.spamhaus.org',
];

$rbl_raw = isset($_POST['rbl_list']) ? (string)$_POST['rbl_list'] : implode("\n", $rbl_default);

$rbls = [];
foreach (preg_split('/\r\n|\r|\n|,/', $rbl_raw) ?: [] as $x) {
    $x = trim((string)$x);
    if ($x === '') continue;
    if (!preg_match('/^[A-Za-z0-9.-]+$/', $x)) continue;
    $rbls[] = $x;
}
$rbls = array_values(array_unique($rbls));

// ==========================
// 4) Header / CSS
// ==========================

if ($isCPanelServer) {
    require_once('/usr/local/cpanel/php/WHM.php');
    WHM::header('Email Solutions', 0, 0);
} else {
    echo '<div class="panel-body">';
}

$img_src = $isCWPServer ? 'design/img/imh-email-solutions.png' : 'imh-email-solutions.png';

?>
<style>
    .panel-body a,
    .imh-box a {
        color: #C52227;
    }

    .panel-body a:hover,
    .imh-box a:hover {
        color: #d33a41;
    }

    .imh-title {
        margin: 0.25em 0 1em 0;
    }

    .imh-title-img {
        margin-right: 0.5em;
        height: 32px;
        width: 32px;
        vertical-align: middle;
    }

    .tabs-nav {
        display: flex;
        flex-wrap: wrap;
        border-bottom: 1px solid #e3e3e3;
        margin-bottom: 1.5em;
        gap: 6px;
    }

    .tabs-nav button {
        border: none;
        background: #f8f8f8;
        color: #333;
        padding: 10px 18px;
        cursor: pointer;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        font-size: 0.95em;
        margin-bottom: -1px;
        border-bottom: 2px solid transparent;
        transition: background 0.15s, border-color 0.15s;
    }

    .tabs-nav button.active {
        background: #fff;
        border-bottom: 2px solid #C52227;
        color: #C52227;
        font-weight: 600;
    }

    .tab-content {
        display: none;
    }

    .tab-content.active {
        display: block;
    }

    .imh-box {
        margin: 1em 0;
        padding: 1em;
        border: 1px solid #ccc;
        border-radius: 8px;
        background: #f9f9f9;
    }

    .imh-box--footer {
        margin: 2em 0;
        padding: 1em;
        border: 1px solid #ccc;
        border-radius: 8px;
    }

    .imh-alert {
        color: #c00;
        margin: 1em 0;
    }

    .imh-pre {
        background: #f8f8f8;
        border: 1px solid #ccc;
        padding: 1em;
        overflow: auto;
    }

    .imh-mono {
        font-family: monospace;
    }

    table.imh-table {
        border-collapse: collapse;
        width: 100%;
        background: #fafcff;
    }

    table.imh-table th,
    table.imh-table td {
        border: 1px solid #000;
        padding: 6px 10px;
        vertical-align: top;
    }

    table.imh-table thead {
        background: #e6f2ff;
        color: #333;
        font-weight: 600;
    }

    tr.imh-alt {
        background: #f4f4f4;
    }

    .imh-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-weight: 700;
        border: 1px solid;
        font-size: 0.9em;
    }

    .imh-badge-ok {
        background: #e6ffee;
        color: #26a042;
        border-color: #8fd19e;
    }

    .imh-badge-bad {
        background: #ffeaea;
        color: #c22626;
        border-color: #e99;
    }

    .imh-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 12px;
    }

    @media (max-width: 900px) {
        .imh-grid {
            grid-template-columns: 1fr;
        }
    }

    .imh-form-row {
        display: flex;
        gap: 10px;
        align-items: center;
        flex-wrap: wrap;
    }

    .imh-form-row label {
        min-width: 160px;
    }

    .imh-form-row input[type="number"],
    .imh-form-row textarea {
        padding: 6px;
    }

    .imh-form-row textarea {
        width: 100%;
        min-height: 120px;
    }
</style>

<h1 class="imh-title"><img src="<?= htmlspecialchars($img_src) ?>" alt="Email Solutions" class="imh-title-img" />Email Solutions</h1>

<div class="tabs-nav" id="imh-tabs-nav">
    <button type="button" class="active" data-tab="tab-dns">DNS Checks</button>
    <button type="button" data-tab="tab-auth">Auth Stats</button>
    <button type="button" data-tab="tab-maillog">Mail Log</button>
    <button type="button" data-tab="tab-queue">Queue</button>
    <button type="button" data-tab="tab-rbl">RBL</button>
    <button type="button" data-tab="tab-conf">Config</button>
</div>

<script>
    (function() {
        function activate(tabId) {
            document.querySelectorAll('#imh-tabs-nav button').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            var btn = document.querySelector('#imh-tabs-nav button[data-tab="' + tabId + '"]');
            var tab = document.getElementById(tabId);
            if (btn) btn.classList.add('active');
            if (tab) tab.classList.add('active');
            try {
                window.location.hash = tabId;
            } catch (e) {}
        }

        document.querySelectorAll('#imh-tabs-nav button').forEach(function(btn) {
            btn.addEventListener('click', function() {
                activate(btn.getAttribute('data-tab'));
            });
        });

        // restore from hash
        if (window.location.hash) {
            var h = window.location.hash.replace('#', '');
            if (document.getElementById(h)) activate(h);
        }
    })();
</script>
<?php

// ==========================
// TAB: DNS Checks
// ==========================

echo '<div id="tab-dns" class="tab-content active">';

echo '<div class="imh-box">'
    . '<p>Validates outbound sending IP address(es) and configured HELO name(s) have sane forward/reverse DNS.</p>'
    . '<p><strong>cPanel files:</strong> <span class="imh-mono">/etc/mailips</span> and <span class="imh-mono">/etc/mailhelo</span><br/>'
    . '<strong>CWP/Postfix:</strong> <span class="imh-mono">/etc/postfix/master.cf</span> transports with <span class="imh-mono">smtp_bind_address</span> and <span class="imh-mono">smtp_helo_name</span></p>'
    . '</div>';

$rows = [];

if ($isCPanelServer) {
    $mailips  = imh_parse_kv_map_file('/etc/mailips');
    $mailhelo = imh_parse_kv_map_file('/etc/mailhelo');

    $keys = array_unique(array_merge(array_keys($mailips), array_keys($mailhelo)));
    sort($keys);

    foreach ($keys as $domain) {
        $ipRaw = $mailips[$domain] ?? '';
        $helo  = $mailhelo[$domain] ?? '';

        foreach (imh_split_ip_list((string)$ipRaw) ?: [''] as $ip) {
            $rows[] = ['source' => 'cPanel', 'scope' => $domain, 'ip' => $ip, 'helo' => $helo];
        }
    }
} elseif ($isCWPServer) {
    $master = imh_read_file_lines('/etc/postfix/master.cf');

    $currentTransport = null;
    $transportDefs = [];

    foreach ($master as $lineRaw) {
        $line = rtrim((string)$lineRaw);
        if ($line === '' || str_starts_with(ltrim($line), '#')) continue;

        if (preg_match('/^([A-Za-z0-9_\-]+)\s+unix\s+.*\s+smtp\s*$/', $line, $m)) {
            $currentTransport = $m[1];
            if (!isset($transportDefs[$currentTransport])) $transportDefs[$currentTransport] = ['ip' => '', 'helo' => ''];
            continue;
        }

        if ($currentTransport && preg_match('/^\s+-o\s+([^=\s]+)=(.+)$/', $line, $m)) {
            $k = trim($m[1]);
            $v = trim($m[2]);
            if ($k === 'smtp_bind_address') $transportDefs[$currentTransport]['ip'] = $v;
            if ($k === 'smtp_helo_name') $transportDefs[$currentTransport]['helo'] = $v;
        }
    }

    foreach ($transportDefs as $name => $def) {
        $ip = trim((string)($def['ip'] ?? ''));
        $helo = trim((string)($def['helo'] ?? ''));
        if ($ip === '' && $helo === '') continue;
        $rows[] = ['source' => 'CWP', 'scope' => 'transport:' . $name, 'ip' => $ip, 'helo' => $helo];
    }
}

if (count($rows) === 0) {
    echo '<div class="imh-box imh-alert">No outbound IP / HELO configuration was detected for this environment.</div>';
} else {
    echo '<div class="imh-box">'
        . '<form method="post" style="display:inline;">'
        . '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($CSRF_TOKEN) . '">'
        . '<button type="submit">Refresh</button>'
        . '</form>'
        . '</div>';

    echo '<div class="imh-box">';
    echo '<table class="imh-table">';
    echo '<thead><tr>'
        . '<th>Source</th><th>Scope</th><th>Outbound IP</th><th>PTR (rDNS)</th><th>PTR resolves back</th>'
        . '<th>HELO</th><th>HELO has A/AAAA</th><th>HELO includes IP</th>'
        . '</tr></thead><tbody>';

    $i = 0;
    foreach ($rows as $r) {
        $i++;
        $alt = ($i % 2 === 0) ? ' class="imh-alt"' : '';

        $ip = trim((string)$r['ip']);
        $helo = rtrim(trim((string)$r['helo']), '.');

        $ptr = ($ip !== '') ? imh_dns_ptr($ip) : '';
        $ptr_ips = ($ptr !== '') ? imh_dns_get_a_aaaa($ptr) : [];
        $ptr_back_ok = ($ip !== '' && $ptr !== '' && in_array($ip, $ptr_ips, true));

        $helo_ips = ($helo !== '') ? imh_dns_get_a_aaaa($helo) : [];
        $helo_has_a = ($helo !== '' && count($helo_ips) > 0);
        $helo_includes_ip = ($ip !== '' && $helo_has_a && in_array($ip, $helo_ips, true));

        echo "<tr$alt>";
        echo '<td>' . htmlspecialchars((string)$r['source']) . '</td>';
        echo '<td class="imh-mono">' . htmlspecialchars((string)$r['scope']) . '</td>';
        echo '<td class="imh-mono">' . htmlspecialchars($ip ?: '-') . '</td>';
        echo '<td class="imh-mono">' . htmlspecialchars($ptr ?: '-') . '</td>';
        echo '<td>' . imh_html_badge($ptr_back_ok, 'OK', 'Mismatch') . '</td>';
        echo '<td class="imh-mono">' . htmlspecialchars($helo ?: '-') . '</td>';
        echo '<td>' . imh_html_badge($helo_has_a, 'OK', 'Missing') . '</td>';
        echo '<td>' . imh_html_badge($helo_includes_ip, 'OK', 'No') . '</td>';
        echo '</tr>';

        echo "<tr$alt><td colspan=\"8\">";
        echo '<div class="imh-mono">'
            . '<strong>PTR A/AAAA:</strong> ' . htmlspecialchars($ptr ? implode(', ', $ptr_ips) : '-') . '<br/>'
            . '<strong>HELO A/AAAA:</strong> ' . htmlspecialchars($helo ? implode(', ', $helo_ips) : '-')
            . '</div>';
        echo '</td></tr>';
    }

    echo '</tbody></table>';
    echo '</div>';
}

echo '</div>'; // tab-dns

// ==========================
// TAB: Auth Stats (cPanel/Exim only)
// ==========================

echo '<div id="tab-auth" class="tab-content">';

echo '<div class="imh-box">'
    . '<p>Summarizes outbound email authentication vectors by scanning <span class="imh-mono">/var/log/exim_mainlog</span> (like MSP\'s <span class="imh-mono">--auth</span>).</p>'
    . '</div>';

if (!$isCPanelServer) {
    echo '<div class="imh-box imh-alert">Auth Stats are currently implemented for cPanel/Exim environments only.</div>';
    echo '</div>';
} else {
    $eximLog = '/var/log/exim_mainlog';
    $raw = imh_read_file($eximLog, $auth_max_bytes);

    if ($raw === '') {
        echo '<div class="imh-box imh-alert">Unable to read ' . htmlspecialchars($eximLog) . ' (missing or not readable).</div>';
        echo '</div>';
    } else {
        $auth_password_hits = [];
        $auth_sendmail_hits = [];
        $auth_local_user_hits = [];
        $subject_hits = [];

        // Regexes (ported from MSP)
        $re_auth_password = '/\sA=dovecot_(login|plain):([^\s]+)\s/';
        $re_sendmail_cwd = '/\scwd=([^\s]+)\s/';
        $re_local_user = '/\sU=([^\s]+)\s.*B=authenticated_local_user/';
        $re_subject = '/\s<=\s.*T="([^"]+)"\s/';

        $lines = preg_split('/\r\n|\r|\n/', $raw);
        if (!is_array($lines)) $lines = [];

        foreach ($lines as $line) {
            $line = (string)$line;
            if ($line === '' || strpos($line, '__cpanel__service__auth__icontact__') !== false) continue;

            if (preg_match($re_auth_password, $line, $m)) {
                $auth_password_hits[] = $m[2] ?? '';
            }
            if (preg_match($re_sendmail_cwd, $line, $m)) {
                $cwd = $m[1] ?? '';
                if ($cwd !== '' && $cwd !== '/' && strpos($cwd, '/var/spool/exim') !== 0) {
                    $auth_sendmail_hits[] = $cwd;
                }
            }
            if (preg_match($re_local_user, $line, $m)) {
                $auth_local_user_hits[] = $m[1] ?? '';
            }
            if (preg_match($re_subject, $line, $m)) {
                $subject_hits[] = $m[1] ?? '';
            }
        }

        echo '<div class="imh-box">'
            . '<form method="post">'
            . '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($CSRF_TOKEN) . '">'
            . '<div class="imh-grid">'
            . '<div>'
            . '<div class="imh-form-row"><label>Max bytes read</label><input type="number" name="auth_max_bytes" value="' . htmlspecialchars((string)$auth_max_bytes) . '" /></div>'
            . '<div class="imh-form-row"><label>Limit (0 = all)</label><input type="number" name="auth_limit" value="' . htmlspecialchars((string)$auth_limit) . '" /></div>'
            . '<div class="imh-form-row"><label>Threshold</label><input type="number" name="auth_threshold" value="' . htmlspecialchars((string)$auth_threshold) . '" /></div>'
            . '</div>'
            . '<div>'
            . '<p class="imh-mono">Log: ' . htmlspecialchars($eximLog) . '</p>'
            . '<button type="submit">Refresh</button>'
            . '</div>'
            . '</div>'
            . '</form>'
            . '</div>';

        $top_password = imh_top_counts($auth_password_hits, $auth_limit, $auth_threshold);
        $top_cwd      = imh_top_counts($auth_sendmail_hits, $auth_limit, $auth_threshold);
        $top_local    = imh_top_counts($auth_local_user_hits, $auth_limit, $auth_threshold);
        $top_subject  = imh_top_counts($subject_hits, $auth_limit, $auth_threshold);

        echo '<div class="imh-box">';
        echo '<h3>Emails sent via Password Authentication</h3>';
        if (count($top_password) === 0) {
            echo '<div class="imh-mono">None</div>';
        } else {
            echo '<div class="imh-pre imh-mono">';
            foreach ($top_password as $k => $v) echo htmlspecialchars(sprintf('%7d %s', $v, $k)) . "\n";
            echo '</div>';
        }
        echo '</div>';

        echo '<div class="imh-box">';
        echo '<h3>Directories where mail was sent via sendmail/script (cwd=...)</h3>';
        if (count($top_cwd) === 0) {
            echo '<div class="imh-mono">None</div>';
        } else {
            echo '<div class="imh-pre imh-mono">';
            foreach ($top_cwd as $k => $v) echo htmlspecialchars(sprintf('%7d %s', $v, $k)) . "\n";
            echo '</div>';
        }
        echo '</div>';

        echo '<div class="imh-box">';
        echo '<h3>Users who sent mail via local SMTP (authenticated_local_user)</h3>';
        if (count($top_local) === 0) {
            echo '<div class="imh-mono">None</div>';
        } else {
            echo '<div class="imh-pre imh-mono">';
            foreach ($top_local as $k => $v) echo htmlspecialchars(sprintf('%7d %s', $v, $k)) . "\n";
            echo '</div>';
        }
        echo '</div>';

        echo '<div class="imh-box">';
        echo '<h3>Subjects by commonality</h3>';
        if (count($top_subject) === 0) {
            echo '<div class="imh-mono">None</div>';
        } else {
            echo '<div class="imh-pre imh-mono">';
            foreach ($top_subject as $k => $v) echo htmlspecialchars(sprintf('%7d %s', $v, $k)) . "\n";
            echo '</div>';
        }
        echo '</div>';

        echo '</div>'; // tab-auth
    }
}

// ==========================
// TAB: Mail Log (cPanel/Exim)
// ==========================

echo '<div id="tab-maillog" class="tab-content">';

echo '<div class="imh-box">'
    . '<p>Scans <span class="imh-mono">/var/log/maillog</span> (and optionally rotated maillogs) for common mail-system error patterns (ported from MSP <span class="imh-mono">--maillog</span>).</p>'
    . '</div>';

if (!$isCPanelServer) {
    echo '<div class="imh-box imh-alert">Mail Log checks are currently implemented for cPanel environments only.</div>';
    echo '</div>';
} else {
    $logdir = '/var/log';
    $rotatedLimit = 5;

    // Discover maillog files
    $files = [];
    $primary = $logdir . '/maillog';
    if (is_file($primary) && is_readable($primary)) $files[] = $primary;

    if ($maillog_rotated && is_dir($logdir) && is_readable($logdir)) {
        $nodes = @scandir($logdir);
        if (is_array($nodes)) {
            $rot = [];
            foreach ($nodes as $n) {
                if (!is_string($n)) continue;
                if (preg_match('/^maillog-/', $n) || preg_match('/^maillog\./', $n)) {
                    $p = $logdir . '/' . $n;
                    if (is_file($p) && is_readable($p)) $rot[] = $p;
                }
            }
            rsort($rot); // newest-ish first depending on naming
            $rot = array_slice($rot, 0, $rotatedLimit);
            $files = array_values(array_unique(array_merge($files, $rot)));
        }
    }

    echo '<div class="imh-box">'
        . '<form method="post">'
        . '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($CSRF_TOKEN) . '">'
        . '<div class="imh-grid">'
        . '<div>'
        . '<div class="imh-form-row"><label>Max bytes per file</label><input type="number" name="maillog_max_bytes" value="' . htmlspecialchars((string)$maillog_max_bytes) . '" /></div>'
        . '<div class="imh-form-row"><label>Limit (0 = all)</label><input type="number" name="maillog_limit" value="' . htmlspecialchars((string)$maillog_limit) . '" /></div>'
        . '<div class="imh-form-row"><label>Threshold</label><input type="number" name="maillog_threshold" value="' . htmlspecialchars((string)$maillog_threshold) . '" /></div>'
        . '<div class="imh-form-row"><label>Include rotated</label><input type="hidden" name="maillog_rotated" value="0" /><input type="checkbox" name="maillog_rotated" value="1" ' . ($maillog_rotated ? 'checked' : '') . ' /></div>'
        . '</div>'
        . '<div>'
        . '<p>Files scanned:</p>'
        . '<div class="imh-pre imh-mono">' . htmlspecialchars(implode("\n", $files ?: ['(none found)'])) . '</div>'
        . '<button type="submit">Refresh</button>'
        . '</div>'
        . '</div>'
        . '</form>'
        . '</div>';

    if (count($files) === 0) {
        echo '<div class="imh-box imh-alert">No maillog files found/readable under /var/log.</div>';
        echo '</div>';
    } else {
        $quota_hits = [];
        $oom_hits = [];
        $pyzor_timeout = 0;
        $pyzor_unreachable = 0;
        $time_backwards = 0;

        // Regexes ported from MSP
        $re_out_of_memory = '/lmtp\(([\w\.@]+)\): Fatal: \S+: Out of memory/';

        $re_quotactl_failed = '/quota-fs: (quotactl\(Q_X?GETQUOTA, [\w\/]+\) failed: .+)/';
        $re_ioctl_failed = '/quota-fs: (ioctl\([\w\/]+, Q_QUOTACTL\) failed: .+)/';
        $re_invalid_nfs = '/quota-fs: (.+ is not a valid NFS device path)/';
        $re_unresponsive_rpc = '/quota-fs: (could not contact RPC service on .+)/';
        $re_rquota_remote = '/quota-fs: (remote( ext)? rquota call failed: .+)/';
        $re_rquota_eacces = '/quota-fs: (permission denied to( ext)? rquota service)/';
        $re_rquota_compile = '/quota-fs: (rquota not compiled with group support)/';
        $re_dovecot_compile = '/quota-fs: (Dovecot was compiled with Linux quota .+)/';
        $re_unrec_code = '/quota-fs: (unrecognized status code .+)/';

        $re_time_backwards = '/Fatal: Time just moved backwards by \d+ \w+\./';
        $re_pyzor_timeout = '/Timeout: Did not receive a response from the pyzor server public\.pyzor\.org/';
        $re_pyzor_unreachable = '/pyzor: check failed: Cannot connect to public\.pyzor\.org:24441: .*Network is unreachable/';

        $per_file = []; // file => counters

        foreach ($files as $fp) {
            $raw = imh_read_file($fp, $maillog_max_bytes);
            if ($raw === '') continue;

            $per_file[$fp] = [
                'bytes' => strlen($raw),
                'quota' => 0,
                'oom' => 0,
                'pyzor_timeout' => 0,
                'pyzor_unreachable' => 0,
                'time_backwards' => 0,
            ];

            $lines = preg_split('/\r\n|\r|\n/', $raw);
            if (!is_array($lines)) $lines = [];

            foreach ($lines as $line) {
                $line = (string)$line;
                if ($line === '') continue;

                if (preg_match($re_out_of_memory, $line, $m)) {
                    $oom_hits[] = $m[1] ?? '';
                    $per_file[$fp]['oom']++;
                }

                if (
                    preg_match($re_quotactl_failed, $line, $m) ||
                    preg_match($re_ioctl_failed, $line, $m) ||
                    preg_match($re_invalid_nfs, $line, $m) ||
                    preg_match($re_unresponsive_rpc, $line, $m) ||
                    preg_match($re_rquota_remote, $line, $m) ||
                    preg_match($re_rquota_eacces, $line, $m) ||
                    preg_match($re_rquota_compile, $line, $m) ||
                    preg_match($re_dovecot_compile, $line, $m) ||
                    preg_match($re_unrec_code, $line, $m)
                ) {
                    $quota_hits[] = $m[1] ?? $line;
                    $per_file[$fp]['quota']++;
                }

                if (preg_match($re_pyzor_timeout, $line)) {
                    $pyzor_timeout++;
                    $per_file[$fp]['pyzor_timeout']++;
                }
                if (preg_match($re_pyzor_unreachable, $line)) {
                    $pyzor_unreachable++;
                    $per_file[$fp]['pyzor_unreachable']++;
                }
                if (preg_match($re_time_backwards, $line)) {
                    $time_backwards++;
                    $per_file[$fp]['time_backwards']++;
                }
            }
        }

        // Summary: give operators a quick sense of "where" the errors are coming from (current vs rotated logs)
        if (isset($per_file) && is_array($per_file) && count($per_file) > 0) {
            $primaryFile = $logdir . '/maillog';
            $primaryCounts = $per_file[$primaryFile] ?? null;

            $primaryHasHits = false;
            if (is_array($primaryCounts)) {
                $primaryHasHits = (
                    ((int)($primaryCounts['quota'] ?? 0)) > 0 ||
                    ((int)($primaryCounts['oom'] ?? 0)) > 0 ||
                    ((int)($primaryCounts['pyzor_timeout'] ?? 0)) > 0 ||
                    ((int)($primaryCounts['pyzor_unreachable'] ?? 0)) > 0 ||
                    ((int)($primaryCounts['time_backwards'] ?? 0)) > 0
                );
            }

            $anyHasHits = false;
            foreach ($per_file as $c) {
                if (!is_array($c)) continue;
                if (
                    ((int)($c['quota'] ?? 0)) > 0 ||
                    ((int)($c['oom'] ?? 0)) > 0 ||
                    ((int)($c['pyzor_timeout'] ?? 0)) > 0 ||
                    ((int)($c['pyzor_unreachable'] ?? 0)) > 0 ||
                    ((int)($c['time_backwards'] ?? 0)) > 0
                ) {
                    $anyHasHits = true;
                    break;
                }
            }

            echo '<div class="imh-box">'
                . '<h3>At-a-glance</h3>';

            if (!$anyHasHits) {
                echo '<p>' . imh_html_badge(true, 'No issues detected', 'Issues detected') . ' in scanned maillogs.</p>';
            } elseif ($primaryHasHits) {
                echo '<p>' . imh_html_badge(false, 'OK', 'Active issues in current maillog') . ' <span class="imh-mono">/var/log/maillog</span></p>';
            } else {
                echo '<p>' . imh_html_badge(false, 'OK', 'Issues only in rotated logs') . ' (no hits in <span class="imh-mono">/var/log/maillog</span>)</p>';
            }

            echo '</div>';

            echo '<div class="imh-box">'
                . '<h3>Time-window / file scope summary</h3>'
                . '<p>This is still summarized output; it helps distinguish whether issues are happening in the current log or primarily in rotated history.</p>'
                . '<table class="imh-table">'
                . '<thead><tr><th>File</th><th>Bytes read</th><th>Quota hits</th><th>OOM hits</th><th>Pyzor timeouts</th><th>Pyzor unreachable</th><th>Time moved backwards</th></tr></thead><tbody>';

            $r = 0;
            foreach ($per_file as $fp => $c) {
                $r++;
                $alt = ($r % 2 === 0) ? ' class="imh-alt"' : '';
                echo "<tr$alt>";
                echo '<td class="imh-mono">' . htmlspecialchars((string)$fp) . '</td>';
                echo '<td class="imh-mono">' . htmlspecialchars((string)($c['bytes'] ?? 0)) . '</td>';
                echo '<td class="imh-mono">' . htmlspecialchars((string)($c['quota'] ?? 0)) . '</td>';
                echo '<td class="imh-mono">' . htmlspecialchars((string)($c['oom'] ?? 0)) . '</td>';
                echo '<td class="imh-mono">' . htmlspecialchars((string)($c['pyzor_timeout'] ?? 0)) . '</td>';
                echo '<td class="imh-mono">' . htmlspecialchars((string)($c['pyzor_unreachable'] ?? 0)) . '</td>';
                echo '<td class="imh-mono">' . htmlspecialchars((string)($c['time_backwards'] ?? 0)) . '</td>';
                echo '</tr>';
            }

            echo '</tbody></table>';
            echo '</div>';
        }

        $top_quota = imh_top_counts($quota_hits, $maillog_limit, $maillog_threshold);
        $top_oom = imh_top_counts($oom_hits, $maillog_limit, $maillog_threshold);

        $quota_lines = [];
        foreach ($top_quota as $k => $v) $quota_lines[] = sprintf('%7d %s', $v, $k);
        $oom_lines = [];
        foreach ($top_oom as $k => $v) $oom_lines[] = sprintf('%7d %s', $v, $k);

        echo '<div class="imh-box">'
            . '<h3>LMTP quota issues</h3>'
            . (count($quota_lines) ? '<div class="imh-pre imh-mono">' . htmlspecialchars(implode("\n", $quota_lines)) . '</div>' : '<div class="imh-mono">None</div>')
            . '</div>';

        echo '<div class="imh-box">'
            . '<h3>Email accounts triggering LMTP Out of memory</h3>'
            . (count($oom_lines) ? '<div class="imh-pre imh-mono">' . htmlspecialchars(implode("\n", $oom_lines)) . '</div>' : '<div class="imh-mono">None</div>')
            . '</div>';

        echo '<div class="imh-box">'
            . '<h3>Spamd/Pyzor connectivity</h3>'
            . '<ul>'
            . '<li>Pyzor timeouts to public.pyzor.org:24441: <span class="imh-mono">' . htmlspecialchars((string)$pyzor_timeout) . '</span></li>'
            . '<li>Pyzor unreachable (network is unreachable): <span class="imh-mono">' . htmlspecialchars((string)$pyzor_unreachable) . '</span></li>'
            . '</ul>'
            . '</div>';

        echo '<div class="imh-box">'
            . '<h3>System time anomalies</h3>'
            . '<p>"Time moved backwards" fatal count: <span class="imh-mono">' . htmlspecialchars((string)$time_backwards) . '</span></p>'
            . '</div>';

        echo '</div>'; // tab-maillog
    }
}

// ==========================
// TAB: Queue
// ==========================

echo '<div id="tab-queue" class="tab-content">';

echo '<div class="imh-box">'
    . '<p>Shows current MTA queue length (Exim only).</p>'
    . '</div>';

if (!$isCPanelServer) {
    echo '<div class="imh-box imh-alert">Queue check is currently implemented for cPanel/Exim environments only.</div>';
} else {
    $queue = null;
    $err = '';

    // Prefer WHM bundled exim in PATH; fallback to /usr/sbin/exim if present.
    $cmd = 'exim -bpc 2>/dev/null';
    $out = @shell_exec($cmd);
    if (is_string($out)) {
        $out = trim($out);
        if ($out !== '' && ctype_digit($out)) $queue = (int)$out;
    }

    if ($queue === null) {
        echo '<div class="imh-box imh-alert">Unable to read Exim queue length (exim -bpc failed).</div>';
    } else {
        $badge = ($queue >= 1000) ? imh_html_badge(false, 'OK', 'High') : imh_html_badge(true, 'OK', 'High');
        echo '<div class="imh-box">'
            . '<h3>Exim Queue</h3>'
            . '<p><span class="imh-mono">' . htmlspecialchars((string)$queue) . '</span> ' . $badge . '</p>'
            . '<form method="post">'
            . '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($CSRF_TOKEN) . '">'
            . '<button type="submit">Refresh</button>'
            . '</form>'
            . '</div>';
    }
}

echo '</div>'; // tab-queue

// ==========================
// TAB: RBL
// ==========================

echo '<div id="tab-rbl" class="tab-content">';

echo '<div class="imh-box">'
    . '<p>Checks outbound IPs against common RBLs via DNS lookups (ported from MSP <span class="imh-mono">--rbl</span>).</p>'
    . '</div>';

if (!$isCPanelServer) {
    echo '<div class="imh-box imh-alert">RBL check is currently implemented for cPanel environments only.</div>';
    echo '</div>';
} else {
    $ips = imh_get_all_outbound_ips_cpanel();

    echo '<div class="imh-box">'
        . '<form method="post">'
        . '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($CSRF_TOKEN) . '">'
        . '<div class="imh-form-row"><label>RBL list (one per line)</label></div>'
        . '<div class="imh-form-row"><textarea name="rbl_list">' . htmlspecialchars($rbl_raw) . '</textarea></div>'
        . '<button type="submit">Run checks</button>'
        . '</form>'
        . '</div>';

    if (count($ips) === 0) {
        echo '<div class="imh-box imh-alert">No IPs discovered to check. (Looked at /var/cpanel/mainip and /etc/mailips)</div>';
    } elseif (count($rbls) === 0) {
        echo '<div class="imh-box imh-alert">No valid RBLs provided.</div>';
    } else {
        echo '<div class="imh-box">';
        echo '<table class="imh-table">';
        echo '<thead><tr><th>IP</th>';
        foreach ($rbls as $rbl) echo '<th>' . htmlspecialchars($rbl) . '</th>';
        echo '</tr></thead><tbody>';

        $row = 0;
        foreach ($ips as $ip) {
            $row++;
            $alt = ($row % 2 === 0) ? ' class="imh-alt"' : '';
            echo "<tr$alt>";
            echo '<td class="imh-mono">' . htmlspecialchars($ip) . '</td>';
            foreach ($rbls as $rbl) {
                $listed = imh_rbl_lookup($ip, $rbl);
                echo '<td>' . ($listed ? imh_html_badge(false, 'Good', 'LISTED') : imh_html_badge(true, 'GOOD', 'LISTED')) . '</td>';
            }
            echo '</tr>';
        }

        echo '</tbody></table>';
        echo '</div>';

        echo '<div class="imh-box">'
            . '<p><strong>Note:</strong> DNS-based RBL checks can be rate-limited by some providers. If results look inconsistent, retry later or use a resolver you control.</p>'
            . '</div>';
    }

    echo '</div>'; // tab-rbl
}

// ==========================
// TAB: Config
// ==========================

echo '<div id="tab-conf" class="tab-content">';

echo '<div class="imh-box">'
    . '<p>Quick configuration checks (ported from MSP <span class="imh-mono">--conf</span>). Focus: reducing common abuse vectors.</p>'
    . '</div>';

if (!$isCPanelServer) {
    echo '<div class="imh-box imh-alert">Config checks are currently implemented for cPanel environments only.</div>';
    echo '</div>';
} else {
    $cpconf = imh_parse_simple_kv_file('/var/cpanel/cpanel.config');
    $eximopts = imh_parse_simple_kv_file('/etc/exim.conf.localopts');
    $dovecot = imh_parse_simple_kv_file('/var/cpanel/conf/dovecot/main');

    echo '<div class="imh-box">'
        . '<form method="post" style="display:inline;">'
        . '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($CSRF_TOKEN) . '">'
        . '<button type="submit">Refresh</button>'
        . '</form>'
        . '</div>';

    echo '<div class="imh-box">';
    echo '<h3>Tweak Settings (/var/cpanel/cpanel.config)</h3>';

    $smtpmailgidonly = ($cpconf['smtpmailgidonly'] ?? '') === '1';
    $nobodyspam      = ($cpconf['nobodyspam'] ?? '') === '1';
    $popbeforesmtp   = ($cpconf['popbeforesmtp'] ?? '') === '0';
    $domainowner_pw  = ($cpconf['domainowner_mail_pass'] ?? '') === '0';

    echo '<ul>';
    echo '<li>Restrict outgoing SMTP to root, exim, and mailman: ' . imh_html_badge($smtpmailgidonly, 'Enabled', 'Disabled') . '</li>';
    echo '<li>Prevent “nobody” from sending mail: ' . imh_html_badge($nobodyspam, 'Enabled', 'Disabled') . '</li>';
    echo '<li>Pop-before-SMTP: ' . imh_html_badge($popbeforesmtp, 'Disabled', 'Enabled') . '</li>';
    echo '<li>Mail auth via domain owner password: ' . imh_html_badge($domainowner_pw, 'Disabled', 'Enabled') . '</li>';
    echo '</ul>';

    echo '</div>';

    echo '<div class="imh-box">';
    echo '<h3>Exim Local Options (/etc/exim.conf.localopts)</h3>';

    $allowweakciphers = ($eximopts['allowweakciphers'] ?? '') === '0';
    $require_secure_auth = ($eximopts['require_secure_auth'] ?? '') === '1';
    $systemfilter = (string)($eximopts['systemfilter'] ?? '');
    $systemfilter_ok = ($systemfilter === '' || $systemfilter === '/etc/cpanel_exim_system_filter');

    echo '<ul>';
    echo '<li>Allow weak SSL/TLS ciphers: ' . imh_html_badge($allowweakciphers, 'Disabled', 'Enabled') . '</li>';
    echo '<li>Require SSL/STARTTLS for auth: ' . imh_html_badge($require_secure_auth, 'Enabled', 'Disabled') . '</li>';
    echo '<li>System filter path: ' . imh_html_badge($systemfilter_ok, 'Default/OK', 'Custom') . ' <span class="imh-mono">' . htmlspecialchars($systemfilter ?: '(unset)') . '</span></li>';
    echo '</ul>';

    echo '</div>';

    echo '<div class="imh-box">';
    echo '<h3>Dovecot (/var/cpanel/conf/dovecot/main)</h3>';

    $protocols = (string)($dovecot['protocols'] ?? '');
    $has_imap = (strpos(' ' . $protocols . ' ', ' imap ') !== false);

    $disable_plaintext_auth = (string)($dovecot['disable_plaintext_auth'] ?? '');
    // On cPanel, good state is often disable_plaintext_auth=yes (require TLS) — MSP warns when it is not "no".
    // We'll mirror MSP behavior: warn if it is not "no".
    $plaintext_auth_disabled = ($disable_plaintext_auth !== 'no');

    echo '<ul>';
    echo '<li>IMAP protocol enabled: ' . imh_html_badge($has_imap, 'Yes', 'No') . ' <span class="imh-mono">' . htmlspecialchars($protocols ?: '(unset)') . '</span></li>';
    echo '<li>Allow plaintext auth: ' . imh_html_badge($plaintext_auth_disabled, 'Disabled', 'Enabled') . ' <span class="imh-mono">disable_plaintext_auth=' . htmlspecialchars($disable_plaintext_auth ?: '(unset)') . '</span></li>';
    echo '</ul>';

    echo '<p><strong>Note:</strong> Dovecot settings vary by cPanel version and TLS policies; treat as guidance, not a verdict.</p>';

    echo '</div>';

    echo '</div>'; // tab-conf
}

// ==========================
// Footer
// ==========================

echo '<div class="imh-box--footer">'
    . '<strong>Email Solutions</strong> v0.1.0 · Root-only plugin · Inspired by cPanel Tech MSP'
    . '</div>';

if ($isCPanelServer) {
    WHM::footer();
} else {
    echo '</div>'; // panel-body
}
