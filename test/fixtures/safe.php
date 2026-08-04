<?php
// Idiomatic, safe PHP. Any finding here is a false positive.

function get_user(PDO $pdo) {
    // Prepared statement — the driver binds the value.
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_GET['id']]);
    return $stmt->fetchAll();
}

function ping() {
    $host = $_POST['host'];
    $allowed = ['api.internal.example'];
    if (!in_array($host, $allowed, true)) {
        return null;
    }
    return shell_exec("ping -c 1 " . escapeshellarg($host));
}

function digest($data) {
    return hash('sha256', $data);
}

$password = getenv('DB_PASSWORD');
