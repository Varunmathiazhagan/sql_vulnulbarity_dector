<?php
$dbFile = __DIR__ . DIRECTORY_SEPARATOR . 'vulnapp.db';
try {
    $pdo = new PDO('sqlite:' . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    // Replace demo attacky texts with neutral copy
    $pdo->exec("UPDATE comments SET comment='Hello world' WHERE comment LIKE '%<b>Hello world</b>%' OR comment LIKE '%Try SQLi like%' OR comment LIKE '%<script%'");
    $pdo->exec("UPDATE uploads SET content='<h1>HTML Content</h1>' WHERE content LIKE '%<script%'");
    $pdo->exec("UPDATE products SET description='Comfy hoodie with premium fabric and clean fit.' WHERE name='Cyber Hoodie'");
    $pdo->exec("UPDATE products SET description='Ceramic mug with a stylish print for late-night sessions.' WHERE name='Pentest Mug'");
    $pdo->exec("UPDATE products SET description='Glossy stickers to customize your laptop and desk.' WHERE name='Sticker Pack'");
    $pdo->exec("UPDATE products SET description='A practical guide with hands-on web techniques.' WHERE name='Web Exploit Book'");
    echo "Sanitization done\n";
} catch (Throwable $e) {
    http_response_code(500);
    echo 'Sanitize failed: ' . $e->getMessage();
}
