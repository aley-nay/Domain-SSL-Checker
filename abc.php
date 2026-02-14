<?php
date_default_timezone_set('Europe/Istanbul');
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);

$jsonFile = 'ssl_listesi.json';
if (!file_exists($jsonFile)) { file_put_contents($jsonFile, json_encode([])); }
$savedDomains = json_decode(file_get_contents($jsonFile), true);

function getDomainDates($domain) {
    $domain = str_replace(['http://', 'https://', '/'], '', trim($domain));
    $whois_server = "whois.iana.org";
    
    $fp = @fsockopen($whois_server, 43, $errno, $errstr, 5);
    if (!$fp) return ["-", "-", 0];
    fputs($fp, $domain . "\r\n");
    $out = "";
    while (!feof($fp)) { $out .= fgets($fp, 128); }
    fclose($fp);
    
    if (preg_match('/refer: (.*)/i', $out, $matches)) {
        $whois_server = trim($matches[1]);
    }

    $fp = @fsockopen($whois_server, 43, $errno, $errstr, 5);
    if (!$fp) return ["-", "-", 0];
    fputs($fp, $domain . "\r\n");
    $out = "";
    while (!feof($fp)) { $out .= fgets($fp, 128); }
    fclose($fp);

    $dStart = "-"; $dEnd = "-"; $dDays = 0;

    if (preg_match('/(Creation Date|Created On|Registration Time|created): (.*)/i', $out, $m)) {
        $dStart = date('d.m.Y', strtotime(trim($m[2])));
    }
    if (preg_match('/(Expiry Date|Expiration Date|Registry Expiry Date|expires): (.*)/i', $out, $m)) {
        $expiryTimestamp = strtotime(trim($m[2]));
        $dEnd = date('d.m.Y', $expiryTimestamp);
        $dDays = floor(($expiryTimestamp - time()) / 86400);
    }

    return [$dStart, $dEnd, (int)$dDays];
}

function getSSLStatus($domain) {
    $cleanDomain = str_replace(['http://', 'https://', '/'], '', trim($domain));
    if (empty($cleanDomain)) return null;

    $status = "❌ Durmuş / Yok";
    $start = "-"; $end = "-"; $issuer = "Bilinmiyor"; $daysLeft = 0;

    $ssl_ctx = stream_context_create(["ssl" => ["capture_peer_cert" => true, "verify_peer" => false, "verify_peer_name" => false]]);
    $client = @stream_socket_client("ssl://" . $cleanDomain . ":443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ssl_ctx);

    if ($client) {
        $params = stream_context_get_params($client);
        fclose($client);
        if (isset($params["options"]["ssl"]["peer_certificate"])) {
            $cert = $params["options"]["ssl"]["peer_certificate"];
            $certData = openssl_x509_parse($cert);
            if ($certData) {
                $start = date('d.m.Y', $certData['validFrom_time_t']);
                $end   = date('d.m.Y', $certData['validTo_time_t']);
                $daysLeft = floor(($certData['validTo_time_t'] - time()) / 86400);
                $issuer = $certData['issuer']['O'] ?? 'Bilinmiyor';
                if ($daysLeft > 0) { $status = "✅ Çalışıyor"; }
            }
        }
    }

    list($d_start, $d_end, $d_days) = getDomainDates($cleanDomain);
    $domain_status = ($d_days > 1) ? "✅ Çalışıyor" : "❌ Süresi Bitmiş";

    return [
        'domain' => $cleanDomain,
        'status' => $status,
        'start'  => $start,
        'end'    => $end,
        'days'   => (int)$daysLeft,
        'issuer' => $issuer,
        'domain_status' => $domain_status,
        'domain_start'  => $d_start,
        'domain_end'    => $d_end,
        'domain_days'   => (int)$d_days
    ];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['domain'])) {
    $res = getSSLStatus($_POST['domain']);
    if ($res) { $savedDomains[$res['domain']] = $res; file_put_contents($jsonFile, json_encode($savedDomains)); }
    header("Location: " . $_SERVER['PHP_SELF']); exit;
}
if (isset($_GET['delete'])) {
    unset($savedDomains[$_GET['delete']]);
    file_put_contents($jsonFile, json_encode($savedDomains));
    header("Location: " . $_SERVER['PHP_SELF']); exit;
}
if (isset($_GET['refresh'])) {
    foreach ($savedDomains as $domain => $data) {
        $res = getSSLStatus($domain);
        if ($res) $savedDomains[$domain] = $res;
    }
    file_put_contents($jsonFile, json_encode($savedDomains));
    header("Location: " . $_SERVER['PHP_SELF']); exit;
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Art Web - Monitor v9.2</title>
<style>
    body { font-family: 'Segoe UI', sans-serif; background: #f4f7f6; margin: 0; display: flex; height: 100vh; }
    .sidebar { width: 320px; background: #fff; padding: 30px; border-right: 1px solid #ddd; }
    .main { flex: 1; padding: 40px; overflow-y: auto; }
    .card { background: #fff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); padding: 25px; }
    input { width: 100%; padding: 12px; border: 2px solid #eee; border-radius: 8px; margin-bottom: 15px; box-sizing: border-box; }
    button { width: 100%; padding: 12px; background: #1a73e8; color: #fff; border: none; border-radius: 8px; cursor: pointer; font-weight: bold; }
    .refresh-btn { background: #28a745; margin-top:10px; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th { background: #f8f9fa; padding: 15px; text-align: left; font-size: 13px; color: #666; border-bottom: 2px solid #eee; }
    td { padding: 15px; border-bottom: 1px solid #f1f1f1; font-size: 14px; }
    .badge { padding: 5px 10px; border-radius: 20px; font-size: 11px; font-weight: bold; }
    .success { background: #d4edda; color: #155724; }
    .danger { background: #f8d7da; color: #721c24; }
    .day-info { font-weight: bold; color: #1a73e8; background: #e8f0fe; padding: 4px 8px; border-radius: 6px; }
</style>
</head>
<body>
<div class="sidebar">
    <h2>Domain Takip</h2>
    <form method="POST">
        <input type="text" name="domain" placeholder="example.com" required>
        <button type="submit">Ekle ve Sorgula</button>
    </form>
    <form method="GET">
        <button type="submit" name="refresh" class="refresh-btn">Tümünü Güncelle</button>
    </form>
</div>
<div class="main">
    <div class="card">
        <h2>Sertifika & Domain Listesi</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>SSL Başlangıç</th>
                    <th>SSL Bitiş</th>
                    <th>SSL Kalan</th>
                    <th>SSL Durum</th>
                    <th>Domain Durum</th>
                    <th>Domain Başlangıç</th>
                    <th>Domain Bitiş</th>
                    <th>Domain Kalan</th>
                    <th>Yayıncı</th>
                    <th>İşlem</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($savedDomains)): ?>
                    <tr><td colspan="11" style="text-align:center; color:#999;">Henüz domain eklenmedi.</td></tr>
                <?php else: ?>
                    <?php foreach (array_reverse($savedDomains) as $domain => $data): ?>
                    <tr>
                        <td><strong><?= htmlspecialchars($domain) ?></strong></td>
                        <td style="color:#888;"><?= $data['start'] ?></td>
                        <td><?= $data['end'] ?></td>
                        <td><span class="day-info"><?= $data['days'] ?> Gün</span></td>
                        <td><span class="badge <?= ($data['status'] == '✅ Çalışıyor') ? 'success' : 'danger' ?>"><?= $data['status'] ?></span></td>
                        <td><span class="badge <?= ($data['domain_status'] == '✅ Çalışıyor') ? 'success' : 'danger' ?>"><?= $data['domain_status'] ?></span></td>
                        <td style="color:#888;"><?= $data['domain_start'] ?></td>
                        <td><?= $data['domain_end'] ?></td>
                        <td><span class="day-info"><?= $data['domain_days'] ?> Gün</span></td>
                        <td style="font-size: 11px; color:#666;"><?= $data['issuer'] ?></td>
                        <td><a href="?delete=<?= urlencode($domain) ?>" style="color:red; text-decoration:none; font-size:12px;">SİL</a></td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
</body>
</html>