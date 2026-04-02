<?php
//Email Solutions

/**
 * Email Solutions (canonical name: "Email Solutions")
 *
 * A WHM/cPanel + CWP root-only plugin focused on outbound email configuration checks.
 *
 * Version: 0.0.1
 *
 * Tabs:
 *   - DNS Checks (default): validates outbound sending IP(s) and HELO names have sane
 *     forward/reverse DNS (A/AAAA and PTR).
 *
 * Relevant sources:
 *   - cPanel: /etc/mailips and /etc/mailhelo
 *   - CWP/Postfix: master.cf transport overrides (smtp_bind_address / smtp_helo_name)
 */

// ==========================
// 1. Environment Detection
// 2. Session & Security
// 3. HTML Header & CSS
// 4. Main Interface
// 5. DNS Checks Tab (default)
// 6. Footer
// ==========================


declare(strict_types=1);

// Polyfill for PHP 5/7
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool
    {
        return $needle === '' || strpos($haystack, $needle) === 0;
    }
}

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
    if (!isset($_SESSION['logged']) || $_SESSION['logged'] != 1 || !isset($_SESSION['username']) || $_SESSION['username'] !== 'root') {
        exit('Access Denied');
    }
}


// ==========================
// 2. Session & Security
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

function imh_read_file_lines(string $path, int $maxBytes = 262144): array
{
    if (!is_file($path) || !is_readable($path)) return [];
    $data = @file_get_contents($path, false, null, 0, $maxBytes);
    if (!is_string($data)) return [];
    $lines = preg_split('/\r\n|\r|\n/', $data);
    if (!is_array($lines)) return [];
    return $lines;
}

function imh_parse_kv_map_file(string $path): array
{
    // Parses files like /etc/mailips and /etc/mailhelo
    // Format: key: value
    // Comments (#) and blank lines ignored.

    $out = [];
    foreach (imh_read_file_lines($path) as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) continue;

        // Strip trailing comments after some whitespace
        $line = preg_replace('/\s+#.*$/', '', $line);
        if (!is_string($line)) continue;

        $parts = explode(':', $line, 2);
        if (count($parts) !== 2) continue;

        $k = strtolower(trim($parts[0]));
        $v = trim($parts[1]);
        if ($k === '' || $v === '') continue;

        $out[$k] = $v;
    }
    return $out;
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

function imh_bool_badge(bool $ok, string $okText = 'OK', string $badText = 'Check'): string
{
    $cls = $ok ? 'imh-badge imh-badge-ok' : 'imh-badge imh-badge-bad';
    $txt = $ok ? $okText : $badText;
    return '<span class="' . $cls . '">' . htmlspecialchars($txt) . '</span>';
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
        $p = trim($p);
        if ($p === '') continue;
        $ips[] = $p;
    }
    return array_values(array_unique($ips));
}


// ==========================
// 3. HTML Header & CSS
// ==========================

if ($isCPanelServer) {
    require_once('/usr/local/cpanel/php/WHM.php');
    WHM::header('Email Solutions WHM Interface', 0, 0);
} else {
    echo '<div class="panel-body">';
}

?>
<style>
    .panel-body a,
    .imh-box a,
    .imh-footer-box a {
        color: #C52227;
    }

    .panel-body a:hover,
    .imh-box a:hover,
    .imh-footer-box a:hover {
        color: #d33a41;
    }

    .imh-title {
        margin: 0.25em 0 1em 0;
    }

    .imh-title-img {
        margin-right: 0.5em;
    }

    .tabs-nav {
        display: flex;
        border-bottom: 1px solid #e3e3e3;
        margin-bottom: 2em;
    }

    .tabs-nav button {
        border: none;
        background: #f8f8f8;
        color: #333;
        padding: 12px 28px;
        cursor: pointer;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        font-size: 1em;
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

    .imh-mono {
        font-family: monospace;
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

    @media (max-width: 700px) {
        table.imh-table {
            font-size: 0.95em;
        }

        .imh-box {
            min-width: 350px;
        }
    }
</style>
<?php


// ==========================
// 4. Main Interface
// ==========================

$img_src = $isCWPServer ? 'design/img/imh-email-solutions.png' : 'imh-email-solutions.png';
echo '<h1 class="imh-title"><img src="' . htmlspecialchars($img_src) . '" alt="Email Solutions" class="imh-title-img" />Email Solutions</h1>';

echo '<div class="tabs-nav" id="imh-tabs-nav">'
    . '<button type="button" class="active" data-tab="tab-dns" aria-label="DNS Checks tab">DNS Checks</button>'
    . '</div>';

?>
<script>
    document.querySelectorAll('#imh-tabs-nav button').forEach(function(btn) {
        btn.addEventListener('click', function() {
            document.querySelectorAll('#imh-tabs-nav button').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            var tabId = btn.getAttribute('data-tab');
            var tab = document.getElementById(tabId);
            if (tab) tab.classList.add('active');
        });
    });
</script>
<?php


// ==========================
// 5. DNS Checks Tab (default)
// ==========================

echo '<div id="tab-dns" class="tab-content active">';

echo '<div class="imh-box">'
    . '<p>This tab validates that outbound email-sending IP address(es) and their configured HELO names have correct forward and reverse DNS (A/AAAA and PTR). Where possible, it also checks that <span class="imh-mono">PTR → A/AAAA</span> resolves back to the same IP (a common deliverability requirement).</p>'
    . '<p><strong>cPanel files:</strong> <span class="imh-mono">/etc/mailips</span> and <span class="imh-mono">/etc/mailhelo</span><br/>'
    . '<strong>CWP/Postfix:</strong> <span class="imh-mono">/etc/postfix/master.cf</span> transports with <span class="imh-mono">smtp_bind_address</span> and <span class="imh-mono">smtp_helo_name</span></p>'
    . '</div>';

// Gather configurations

$rows = [];

if ($isCPanelServer) {
    $mailips  = imh_parse_kv_map_file('/etc/mailips');
    $mailhelo = imh_parse_kv_map_file('/etc/mailhelo');

    // Normalize: include all domains present in either file
    $keys = array_unique(array_merge(array_keys($mailips), array_keys($mailhelo)));
    sort($keys);

    foreach ($keys as $domain) {
        $ipRaw = $mailips[$domain] ?? '';
        $helo  = $mailhelo[$domain] ?? '';

        foreach (imh_split_ip_list($ipRaw) ?: [''] as $ip) {
            $rows[] = [
                'source' => 'cPanel',
                'scope'  => $domain,
                'ip'     => $ip,
                'helo'   => $helo,
            ];
        }
    }
} elseif ($isCWPServer) {
    // CWP uses Postfix. Dedicated IP + HELO per-sender is commonly implemented via:
    // - sender_dependent_default_transport_maps (main.cf)
    // - custom transports in master.cf with smtp_bind_address and smtp_helo_name

    // --- 1) Parse master.cf for smtp transport definitions ---
    $master = imh_read_file_lines('/etc/postfix/master.cf');

    $currentTransport = null;
    $transportDefs = []; // name => ['ip'=>..., 'helo'=>...]

    foreach ($master as $lineRaw) {
        $line = rtrim((string)$lineRaw);
        if ($line === '' || str_starts_with(ltrim($line), '#')) continue;

        // Transport header line: "name  unix  -  -  ...  smtp"
        if (preg_match('/^([A-Za-z0-9_\-]+)\s+unix\s+.*\s+smtp\s*$/', $line, $m)) {
            $currentTransport = $m[1];
            if (!isset($transportDefs[$currentTransport])) {
                $transportDefs[$currentTransport] = ['ip' => '', 'helo' => ''];
            }
            continue;
        }

        // Option continuation lines begin with whitespace
        if ($currentTransport && preg_match('/^\s+-o\s+([^=\s]+)=(.+)$/', $line, $m)) {
            $k = trim($m[1]);
            $v = trim($m[2]);

            if ($k === 'smtp_bind_address') {
                $transportDefs[$currentTransport]['ip'] = $v;
            }
            if ($k === 'smtp_helo_name') {
                $transportDefs[$currentTransport]['helo'] = $v;
            }
        }
    }

    // --- 2) Parse main.cf to find sender-dependent transport map ---
    $mapPath = '';
    $main = imh_read_file_lines('/etc/postfix/main.cf');
    foreach ($main as $lineRaw) {
        $line = preg_replace('/\s+#.*$/', '', trim((string)$lineRaw));
        if (!is_string($line)) continue;
        if ($line === '' || str_starts_with($line, '#')) continue;

        if (preg_match('/^sender_dependent_default_transport_maps\s*=\s*(.+)$/', $line, $m)) {
            $rhs = trim($m[1]);
            // Common: regexp:/etc/postfix/sdd_transport_maps.regexp
            // Also possible: hash:/path, pcre:/path, texthash:/path, etc.
            if (preg_match('/^(?:regexp|pcre|hash|texthash):(.+)$/', $rhs, $m2)) {
                $mapPath = trim($m2[1]);
            } elseif (preg_match('/^\/?etc\/postfix\/.+/', $rhs)) {
                // Bare path
                $mapPath = $rhs;
            }
            break;
        }
    }

    // --- 3) If we have a regexp map, load sender->transport selectors ---
    $selectors = []; // [['selector'=>..., 'transport'=>...], ...]
    if ($mapPath !== '' && is_file($mapPath) && is_readable($mapPath)) {
        foreach (imh_read_file_lines($mapPath) as $lineRaw) {
            $line = preg_replace('/\s+#.*$/', '', trim((string)$lineRaw));
            if (!is_string($line)) continue;
            if ($line === '') continue;

            // Wiki format example:
            // /@customer1-dom\.tld$/ customer1:
            if (preg_match('#^(/.+/)[\s\t]+([A-Za-z0-9_\-]+):\s*$#', $line, $m)) {
                $selectors[] = [
                    'selector'  => $m[1],
                    'transport' => $m[2],
                ];
            }
        }
    }

    // --- 4) Build rows ---
    if (count($selectors) > 0) {
        // Prefer mapped view: selector -> transport -> IP/HELO
        foreach ($selectors as $sel) {
            $t = $sel['transport'];
            $def = $transportDefs[$t] ?? ['ip' => '', 'helo' => ''];
            $ip = trim((string)($def['ip'] ?? ''));
            $helo = trim((string)($def['helo'] ?? ''));
            if ($ip === '' && $helo === '') continue;
            $rows[] = [
                'source' => 'CWP',
                'scope'  => 'sender-map ' . $sel['selector'] . ' → transport:' . $t,
                'ip'     => $ip,
                'helo'   => $helo,
            ];
        }
    } else {
        // Fallback: just list transports
        foreach ($transportDefs as $name => $def) {
            $ip = trim((string)($def['ip'] ?? ''));
            $helo = trim((string)($def['helo'] ?? ''));
            if ($ip === '' && $helo === '') continue;
            $rows[] = [
                'source' => 'CWP',
                'scope'  => 'transport:' . $name,
                'ip'     => $ip,
                'helo'   => $helo,
            ];
        }
    }
}

if (count($rows) === 0) {
    echo '<div class="imh-box imh-alert">No outbound IP / HELO configuration was detected for this environment.</div>';
    echo '</div>'; // tab
} else {

    // Render table
    echo '<div class="imh-box">'
        . '<form method="post" style="display:inline;">'
        . '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($CSRF_TOKEN) . '">'
        . '<button type="submit">Refresh</button>'
        . '</form>'
        . '</div>';

    echo '<div class="imh-box">';
    echo '<table class="imh-table">';
    echo '<thead><tr>'
        . '<th>Source</th>'
        . '<th>Scope</th>'
        . '<th>Outbound IP</th>'
        . '<th>PTR (rDNS)</th>'
        . '<th>PTR resolves back to IP</th>'
        . '<th>HELO</th>'
        . '<th>HELO has A/AAAA</th>'
        . '<th>HELO includes IP</th>'
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
        echo '<td>' . imh_bool_badge($ptr_back_ok, 'OK', 'Mismatch') . '</td>';

        echo '<td class="imh-mono">' . htmlspecialchars($helo ?: '-') . '</td>';
        echo '<td>' . imh_bool_badge($helo_has_a, 'OK', 'Missing') . '</td>';
        echo '<td>' . imh_bool_badge($helo_includes_ip, 'OK', 'No') . '</td>';

        echo '</tr>';

        // Details row
        echo "<tr$alt><td colspan=\"8\">";
        echo '<div class="imh-mono">';
        echo '<strong>PTR A/AAAA:</strong> ' . htmlspecialchars($ptr ? implode(', ', $ptr_ips) : '-') . '<br/>';
        echo '<strong>HELO A/AAAA:</strong> ' . htmlspecialchars($helo ? implode(', ', $helo_ips) : '-') . '</div>';
        echo '</td></tr>';
    }

    echo '</tbody></table>';
    echo '</div>';

    echo '<div class="imh-box">'
        . '<h3>Interpretation notes</h3>'
        . '<ul>'
        . '<li><strong>PTR resolves back to IP</strong>: the PTR hostname should have an A/AAAA that contains the same IP. Many receivers expect forward-confirmed reverse DNS.</li>'
        . '<li><strong>HELO includes IP</strong>: HELO name is usually best when it also resolves to the sending IP (or at least to a stable, authorized host on the same server).</li>'
        . '<li>If you change outgoing IP(s), ensure SPF for the sending domain(s) is updated accordingly.</li>'
        . '</ul>'
        . '</div>';

    echo '</div>'; // tab
}


// ==========================
// 6. Footer
// ==========================

echo '<div class="imh-box--footer">'
    . '<strong>Email Solutions</strong> v0.0.1 · Root-only plugin · Canonical name: <em>Email Solutions</em>'
    . '</div>';

if ($isCPanelServer) {
    WHM::footer();
} else {
    echo '</div>'; // panel-body
}
