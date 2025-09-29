<?php require __DIR__ . '/config.php';

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // No validation of file type or size to allow security testing
    if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
        $name = $_FILES['file']['name'];
        $tmp = $_FILES['file']['tmp_name'];
        $content = file_get_contents($tmp);
        // Save to uploads folder (no sanitization, potential overwrite)
        $dest = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . $name;
        @move_uploaded_file($tmp, $dest);
        // Also store content in DB as TEXT
        $sql = "INSERT INTO uploads (filename, content) VALUES ('$name', '" . str_replace("'", "''", $content) . "')"; // naive escaping, still vulnerable
        try {
            db()->exec($sql);
            $msg = '<p class="success">Uploaded ' . $name . '.</p>';
        } catch (Throwable $e) {
            $msg = '<p class="danger">Error: ' . $e->getMessage() . '</p>';
        }
    } else {
        $msg = '<p class="danger">Upload failed.</p>';
    }
}

$files = db()->query('SELECT id, filename FROM uploads ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);
?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnApp - Upload</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<?php nav(); ?>
<div class="hero"><div class="container">
    <h1>File Uploads</h1>
    <p class="sub">Manage your files.</p>
</div></div>
<div class="container">
    <?php echo $msg; ?>
    <div class="card">
    <form method="post" action="/upload.php" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button>
    </form>
    </div>

    <div class="card">
    <h2 class="flex space-between">Uploaded Files <span class="badge">Latest</span></h2>
    <ul style="list-style:none; padding-left:0;">
        <?php foreach ($files as $f): ?>
            <li>
                <a href="/uploads/<?php echo $f['filename']; ?>" target="_blank"><?php echo $f['filename']; ?></a>
                - <a href="/view_upload.php?id=<?php echo $f['id']; ?>">view in DB</a>
            </li>
        <?php endforeach; ?>
    </ul>
    </div>
    
</div>
</body>
</html>
