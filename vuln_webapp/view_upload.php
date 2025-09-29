<?php require __DIR__ . '/config.php';

$id = isset($_GET['id']) ? $_GET['id'] : '0';
$row = db()->query("SELECT id, filename, content FROM uploads WHERE id = $id")->fetch(PDO::FETCH_ASSOC); // vulnerable SQLi
if (!$row) {
    http_response_code(404);
    echo 'Not found';
    exit;
}
?><!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnApp - View Upload</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<?php nav(); ?>
<div class="hero"><div class="container">
    <h1>View Upload</h1>
    <p class="sub">File: <?php echo $row['filename']; ?></p>
</div></div>
<div class="container">
    <div class="card">
        <pre style="white-space: pre-wrap; background:#0b1736; border:1px solid var(--border); padding:12px; border-radius:10px; color: var(--text); "><?php echo $row['content']; ?></pre>
    </div>
    
    <a class="btn-outline" href="/upload.php">Back</a>
</div>
</body>
</html>
