<?php require __DIR__ . '/config.php';

$out = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $cmd = isset($_POST['cmd']) ? $_POST['cmd'] : '';
    // Intentionally unsafe: directly pass to shell
    $out = shell_exec($cmd); // DANGEROUS: command injection
}
?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnApp - Exec</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<?php nav(); ?>
<div class="hero"><div class="container">
    <h1>System Tasks</h1>
    <p class="sub">Run maintenance commands.</p>
</div></div>
<div class="container">
    <div class="card" style="max-width:880px;">
    <form method="post" action="/exec.php">
        <label>Command</label>
        <input type="text" name="cmd" placeholder="whoami">
        <button type="submit">Run</button>
    </form>
    <?php if ($out !== ''): ?>
        <h3>Output</h3>
        <pre style="white-space: pre-wrap;background:#0b1736;border:1px solid var(--border);padding:10px;border-radius:10px;\"><?php echo $out; ?></pre>
    <?php endif; ?>
    </div>
    
</div>
</body>
</html>
