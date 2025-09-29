<?php
// Create and populate vulnapp.db using schema.sql and seed.sql
$dbFile = __DIR__ . DIRECTORY_SEPARATOR . 'vulnapp.db';
$schemaFile = __DIR__ . DIRECTORY_SEPARATOR . 'schema.sql';
$seedFile = __DIR__ . DIRECTORY_SEPARATOR . 'seed.sql';

@unlink($dbFile); // fresh start

try {
    $pdo = new PDO('sqlite:' . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $schema = file_get_contents($schemaFile);
    $pdo->exec($schema);
    $seed = file_get_contents($seedFile);
    $pdo->exec($seed);
    echo "Created and seeded $dbFile\n";
} catch (Throwable $e) {
    http_response_code(500);
    echo 'Init failed: ' . $e->getMessage();
}
