<?php
// Deliberately vulnerable PHP fixture.

// VULN: SQL Injection — concatenation into mysqli_query()
function get_user($conn) {
    $id = $_GET['id'];
    return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
}

// VULN: Command Injection — shell_exec with untrusted input
function ping() {
    $host = $_POST['host'];
    return shell_exec("ping -c 1 " . $host);
}

// VULN: Insecure Crypto — MD5
function digest($data) {
    return md5($data);
}

// VULN: Hardcoded Secret
$password = "s3cr3t-production-value";
