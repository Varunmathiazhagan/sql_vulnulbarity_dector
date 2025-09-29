<?php require __DIR__ . '/config.php';

$u = current_user();
if (!$u) {
    header('Location: /login.php');
    exit;
}

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $comment = isset($_POST['comment']) ? $_POST['comment'] : '';
    try {
        $sql = "INSERT INTO comments (user_id, comment) VALUES ({$u['id']}, '$comment')"; // vulnerable SQLi/XSS
        db()->exec($sql);
        $msg = '<p class="success">Comment submitted.</p>';
    } catch (Throwable $e) {
        $msg = '<p class="danger">Error: ' . $e->getMessage() . '</p>';
    }
}

?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnApp - New Comment</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<?php nav(); ?>
<div class="hero"><div class="container">
    <h1>New Comment</h1>
    <p class="sub">Logged in as <?php echo htmlspecialchars($u['username']); ?></p>
</div></div>
<div class="container">
    <?php echo $msg; ?>
    <div class="card" style="max-width:760px;">
    <form method="post" action="/comment.php">
        <label>Comment</label>
        <textarea name="comment" rows="4" placeholder="Write anything (HTML/JS allowed for XSS testing)"></textarea>
        <button type="submit">Post</button>
    </form>
    </div>
    
</div>
</body>
</html>
