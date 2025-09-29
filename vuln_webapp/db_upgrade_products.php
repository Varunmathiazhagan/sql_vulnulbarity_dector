<?php
$dbFile = __DIR__ . DIRECTORY_SEPARATOR . 'vulnapp.db';
try {
    $pdo = new PDO('sqlite:' . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      description TEXT,
      price REAL,
      image TEXT
    )');
    // Seed only if empty
    $count = (int)$pdo->query('SELECT COUNT(*) FROM products')->fetchColumn();
    if ($count === 0) {
        $seed = file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . 'seed.sql');
        // naive approach: extract only the products inserts
        foreach (explode(";", $seed) as $stmt) {
            if (stripos($stmt, 'INSERT INTO products') !== false) {
                $pdo->exec($stmt);
            }
        }
        echo "Products table created and seeded\n";
    } else {
        echo "Products table already has data\n";
    }
} catch (Throwable $e) {
    http_response_code(500);
    echo 'Upgrade failed: ' . $e->getMessage();
}
