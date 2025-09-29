<?php require __DIR__ . '/config.php'; 
// Initialize data BEFORE HTML so variables exist when rendering
// GET search vulnerable to SQL injection (no parameterization)
$search = isset($_GET['q']) ? $_GET['q'] : '';
$where = '';
if ($search !== '') {
    // vulnerable: concatenating directly into SQL
    $where = "WHERE username LIKE '%$search%'";
}

// POST add comment vulnerable to XSS and missing CSRF
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_comment'])) {
    $uid = isset($_POST['user_id']) ? $_POST['user_id'] : '';
    $comment = isset($_POST['comment']) ? $_POST['comment'] : '';
    try {
        $sql = "INSERT INTO comments (user_id, comment) VALUES ($uid, '$comment')"; // vulnerable to SQLi and XSS on render
        db()->exec($sql);
        $msg = '<p class="success">Comment added.</p>';
    } catch (Throwable $e) {
        $msg = '<p class="danger">Error: ' . $e->getMessage() . '</p>';
    }
}

// Fetch users
$users = db()->query("SELECT id, username, password FROM users $where ORDER BY id ASC")->fetchAll(PDO::FETCH_ASSOC);

// Fetch comments joined (no escaping on output to allow XSS testing)
$comments = db()->query("SELECT c.id, c.user_id, c.comment, u.username FROM comments c LEFT JOIN users u ON u.id = c.user_id ORDER BY c.id DESC")->fetchAll(PDO::FETCH_ASSOC);
?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnApp - Home</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<?php nav(); ?>
<div class="hero"><div class="container">
    <h1>VulnStore</h1>
    <p class="sub">Your one‑stop demo storefront.</p>
</div></div>

<div class="container grid">
    <aside class="panel">
    <h3>Search Users</h3>
        <form method="get" action="/index.php">
            <input type="text" name="q" placeholder="username contains..." value="<?php echo $search; ?>">
            <button type="submit">Search</button>
        </form>

        
    </aside>

    <main>
        <div class="card">
            <h2 class="flex space-between">All Users <span class="badge">Directory</span></h2>
            <table>
                <thead><tr><th>ID</th><th>Username</th></tr></thead>
                <tbody>
                <?php foreach ($users as $u): ?>
                    <tr>
                        <td><?php echo $u['id']; ?></td>
                        <td><?php echo $u['username']; ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

    <?php // logic moved to top so variables exist when rendering ?>

        <div class="card">
            <h2 class="flex space-between">Comments <span class="badge">Activity</span></h2>
            <?php echo $msg; ?>
            <form method="post" action="/index.php">
                <div class="grid" style="grid-template-columns: 140px 1fr; gap: 16px;">
                    <div>
                        <label>User ID</label>
                        <input type="text" name="user_id" placeholder="e.g., 1">
                    </div>
                    <div>
                        <label>Comment</label>
                        <textarea name="comment" rows="3" placeholder="Write a comment..."></textarea>
                    </div>
                </div>
                <input type="hidden" name="add_comment" value="1">
                <button type="submit">Submit</button>
            </form>

            <?php if ($comments): ?>
                <table>
                    <thead><tr><th>ID</th><th>User</th><th>Comment</th></tr></thead>
                    <tbody>
                    <?php foreach ($comments as $c): ?>
                        <tr>
                            <td><?php echo $c['id']; ?></td>
                            <td><?php echo $c['username']; ?></td>
                            <td><?php echo $c['comment']; ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </main>
</div>
<?php footer_note(); ?>
</body>
</html>
