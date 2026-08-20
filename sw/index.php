<?php
// ============================================================
// نظام الصادر والوارد — نسخة الملف الواحد
// PHP + SQLite مدمجة — ارفع هذا الملف فقط لاستضافتك ويعمل فورًا
// ============================================================

declare(strict_types=1);

// ---------------- الإعدادات والجلسة الآمنة ----------------
define('APP_NAME', 'نظام الصادر والوارد');
date_default_timezone_set('Asia/Riyadh');

// إنشاء مجلد البيانات وحمايته تلقائيًا عند أول تشغيل
define('DATA_DIR', __DIR__ . '/data');
if (!is_dir(DATA_DIR)) {
    @mkdir(DATA_DIR, 0775, true);
    @file_put_contents(DATA_DIR . '/.htaccess', "Require all denied\nDeny from all\n");
    @file_put_contents(DATA_DIR . '/index.html', '');
}
define('DB_PATH', DATA_DIR . '/app.db');

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

session_name('SADIR_WARID_SESSION');
session_set_cookie_params([
    'lifetime' => 60 * 60 * 8,
    'path'     => '/',
    'secure'   => $isHttps,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
ini_set('display_errors', '0');
error_reporting(E_ALL);

// ---------------- قاعدة البيانات المدمجة (SQLite) ----------------
function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $isNew = !file_exists(DB_PATH);
    $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA busy_timeout = 5000');
    createSchema($pdo);
    if ($isNew) {
        seedDefaults($pdo);
    }
    return $pdo;
}

function createSchema(PDO $pdo): void
{
    $pdo->exec(<<<SQL
CREATE TABLE IF NOT EXISTS departments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    code       TEXT NOT NULL UNIQUE,
    is_active  INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    name          TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'employee' CHECK (role IN ('admin','employee')),
    dept_id       INTEGER REFERENCES departments(id),
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    last_login    TEXT
);
CREATE TABLE IF NOT EXISTS correspondence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dept_id     INTEGER NOT NULL REFERENCES departments(id),
    type        TEXT NOT NULL CHECK (type IN ('outgoing','incoming')),
    year        INTEGER NOT NULL,
    serial      INTEGER NOT NULL,
    ref_number  TEXT NOT NULL UNIQUE,
    subject     TEXT NOT NULL,
    entity      TEXT NOT NULL,
    cdate       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','in_progress','completed','archived')),
    priority    TEXT NOT NULL DEFAULT 'normal' CHECK (priority IN ('normal','urgent','very_urgent')),
    notes       TEXT,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_by  INTEGER REFERENCES users(id),
    updated_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_corr_dept   ON correspondence(dept_id, type, year);
CREATE INDEX IF NOT EXISTS idx_corr_date   ON correspondence(cdate);
CREATE INDEX IF NOT EXISTS idx_corr_status ON correspondence(status);
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    username   TEXT NOT NULL,
    action     TEXT NOT NULL,
    details    TEXT,
    ip         TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, created_at);
SQL);
}

function seedDefaults(PDO $pdo): void
{
    $depts = [
        ['الإدارة العامة', 'ADM'],
        ['الإدارة المالية', 'FIN'],
        ['إدارة الموارد البشرية', 'HR'],
    ];
    $stmt = $pdo->prepare('INSERT OR IGNORE INTO departments (name, code) VALUES (?, ?)');
    foreach ($depts as $d) {
        $stmt->execute($d);
    }
    if ((int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() === 0) {
        $pdo->prepare('INSERT INTO users (username, password_hash, name, role, dept_id) VALUES (?, ?, ?, ?, NULL)')
            ->execute(['admin', password_hash('Admin@123456', PASSWORD_BCRYPT), 'مدير النظام', 'admin']);
    }
}

// ---------------- المصادقة ----------------
function currentUser(): ?array
{
    if (empty($_SESSION['user_id'])) {
        return null;
    }
    static $user = null;
    if ($user === null) {
        $stmt = db()->prepare(
            'SELECT u.*, d.name AS dept_name, d.code AS dept_code
             FROM users u LEFT JOIN departments d ON d.id = u.dept_id
             WHERE u.id = ? AND u.is_active = 1'
        );
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch() ?: false;
        if (!$user) {
            session_destroy();
            return null;
        }
    }
    return $user ?: null;
}

function requireLogin(): array
{
    $user = currentUser();
    if (!$user) {
        header('Location: ?page=login');
        exit;
    }
    return $user;
}

function requireAdmin(array $user): void
{
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        exit('هذه الصفحة تتطلب صلاحية مدير النظام');
    }
}

function attemptLogin(string $username, string $password): bool
{
    $stmt = db()->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([trim($username)]);
    $user = $stmt->fetch();
    if (!$user || !password_verify($password, $user['password_hash'])) {
        audit(null, $username, 'فشل تسجيل دخول', 'محاولة دخول خاطئة');
        return false;
    }
    if (!$user['is_active']) {
        return false;
    }
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int) $user['id'];
    db()->prepare("UPDATE users SET last_login = datetime('now','localtime') WHERE id = ?")
        ->execute([$user['id']]);
    audit((int) $user['id'], $user['username'], 'تسجيل دخول', 'دخول ناجح');
    return true;
}

function logoutUser(): void
{
    $user = currentUser();
    if ($user) {
        audit((int) $user['id'], $user['username'], 'تسجيل خروج', '');
    }
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], '', $p['secure'], $p['httponly']);
    }
    session_destroy();
}

function audit(?int $userId, string $username, string $action, string $details): void
{
    db()->prepare('INSERT INTO audit_log (user_id, username, action, details, ip) VALUES (?, ?, ?, ?, ?)')
        ->execute([$userId, $username, $action, $details, $_SERVER['REMOTE_ADDR'] ?? '']);
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}
function csrfField(): string
{
    return '<input type="hidden" name="csrf" value="' . csrfToken() . '">';
}
function checkCsrf(): void
{
    $token = $_POST['csrf'] ?? '';
    if (!$token || !hash_equals($_SESSION['csrf'] ?? '', $token)) {
        http_response_code(403);
        exit('طلب غير صالح (CSRF)');
    }
}

// ---------------- دوال مساعدة ----------------
function e(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}
function flash(string $type, string $message): void
{
    $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
}
function renderFlash(): void
{
    foreach ($_SESSION['flash'] ?? [] as $f) {
        echo '<div class="alert alert-' . e($f['type']) . '">' . e($f['message']) . '</div>';
    }
    unset($_SESSION['flash']);
}

const TYPE_LABELS = ['outgoing' => 'صادر', 'incoming' => 'وارد'];
const STATUS_LABELS = ['new' => 'جديدة', 'in_progress' => 'قيد المعالجة', 'completed' => 'مكتملة', 'archived' => 'مؤرشفة'];
const PRIORITY_LABELS = ['normal' => 'عادية', 'urgent' => 'عاجلة', 'very_urgent' => 'عاجلة جدًا'];
const ROLE_LABELS = ['admin' => 'مدير النظام', 'employee' => 'موظف'];

function statusBadge(string $status): string
{
    return '<span class="badge status-' . e($status) . '">' . e(STATUS_LABELS[$status] ?? $status) . '</span>';
}
function priorityBadge(string $priority): string
{
    return '<span class="badge priority-' . e($priority) . '">' . e(PRIORITY_LABELS[$priority] ?? $priority) . '</span>';
}
function typeBadge(string $type): string
{
    $class = $type === 'outgoing' ? 'type-out' : 'type-in';
    return '<span class="badge ' . $class . '">' . e(TYPE_LABELS[$type] ?? $type) . '</span>';
}

function exportCsv(string $filename, array $header, array $rows): void
{
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    echo "\xEF\xBB\xBF";
    $out = fopen('php://output', 'w');
    fputcsv($out, $header);
    foreach ($rows as $row) {
        fputcsv($out, $row);
    }
    fclose($out);
    exit;
}

function allowedDepartments(array $user): array
{
    if ($user['role'] === 'admin') {
        return db()->query('SELECT * FROM departments WHERE is_active = 1 ORDER BY id')->fetchAll();
    }
    if (!$user['dept_id']) {
        return [];
    }
    $stmt = db()->prepare('SELECT * FROM departments WHERE id = ? AND is_active = 1');
    $stmt->execute([$user['dept_id']]);
    return $stmt->fetchAll();
}
function canAccessDept(array $user, int $deptId): bool
{
    return $user['role'] === 'admin' || (int) $user['dept_id'] === $deptId;
}
function canModifyRecord(array $user, array $record): bool
{
    return $user['role'] === 'admin' || (int) $record['created_by'] === (int) $user['id'];
}

// معاينة الرقم المرجعي التالي لإدارة معينة
function peekNextRef(int $deptId, string $type): string
{
    $stmt = db()->prepare(
        'SELECT d.code, COALESCE(MAX(c.serial),0)+1 AS next_serial
         FROM departments d
         LEFT JOIN correspondence c ON c.dept_id = d.id AND c.type = ? AND c.year = ?
         WHERE d.id = ? GROUP BY d.id'
    );
    $stmt->execute([$type, (int) date('Y'), $deptId]);
    $row = $stmt->fetch();
    if (!$row) {
        return '';
    }
    return sprintf('%s-%s-%d-%04d', $row['code'], $type === 'outgoing' ? 'OUT' : 'IN', (int) date('Y'), (int) $row['next_serial']);
}

// ---------------- التنسيقات المدمجة ----------------
function printCss(): void
{
    echo '<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--primary:#0f5e57;--primary-dark:#0b4a44;--bg:#f1f5f4;--card:#fff;--border:#dde5e3;--text:#1e2a28;--muted:#6b7a77;--danger:#c0392b}
body{font-family:"Segoe UI",Tahoma,"Noto Kufi Arabic",Arial,sans-serif;background:var(--bg);color:var(--text);font-size:15px;line-height:1.6}
.app{display:flex;min-height:100vh}
.sidebar{width:250px;background:linear-gradient(180deg,#0b4a44,#0f5e57);color:#fff;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;flex-shrink:0}
.brand{display:flex;align-items:center;gap:12px;padding:20px;border-bottom:1px solid rgba(255,255,255,.12)}
.brand-icon{width:44px;height:44px;border-radius:12px;background:rgba(255,255,255,.12);display:flex;align-items:center;justify-content:center;font-size:22px}
.brand-name{font-weight:700;font-size:16px}
.brand-sub{font-size:12px;color:#bfe3dd}
.sidebar nav{flex:1;padding:14px 10px;display:flex;flex-direction:column;gap:4px}
.nav-link{display:flex;align-items:center;gap:10px;color:#d7ece9;text-decoration:none;padding:10px 14px;border-radius:8px;font-weight:500;transition:background .15s}
.nav-link:hover{background:rgba(255,255,255,.08);color:#fff}
.nav-link.active{background:rgba(255,255,255,.16);color:#fff}
.nav-icon{width:22px;text-align:center}
.sidebar-user{padding:16px 20px;border-top:1px solid rgba(255,255,255,.12)}
.user-name{font-weight:700}
.user-meta{font-size:12px;color:#bfe3dd}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{background:var(--card);border-bottom:1px solid var(--border);padding:14px 26px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
.topbar h1{font-size:19px}
.topbar-actions{display:flex;gap:8px}
.content{padding:24px 26px;display:flex;flex-direction:column;gap:18px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px}
.card-title{font-size:16px;margin-bottom:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.card.stat{display:flex;align-items:center;gap:14px;padding:16px}
.stat-icon{width:50px;height:50px;border-radius:12px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:22px;color:#fff}
.bg-slate{background:#455a64}.bg-teal{background:#0f766e}.bg-indigo{background:#4338ca}.bg-amber{background:#d97706}
.stat-num{font-size:24px;font-weight:800}
.stat-label{font-size:13px;color:var(--muted)}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:900px){.grid-2{grid-template-columns:1fr}}
.table-wrap{overflow-x:auto}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:10px 12px;text-align:right;border-bottom:1px solid var(--border);white-space:nowrap}
.table th{background:#f7faf9;font-size:13px;color:var(--muted);font-weight:600}
.table tbody tr:hover{background:#f7faf9}
.empty{text-align:center;color:var(--muted);padding:32px !important}
.truncate{max-width:220px;overflow:hidden;text-overflow:ellipsis}
.actions{display:flex;gap:6px;align-items:center}
code{background:#eef3f2;padding:2px 7px;border-radius:6px;font-size:12.5px}
.dept-code{background:#0f5e57;color:#fff;font-weight:700}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600;border:1px solid transparent}
.status-new{background:#e3f2fd;color:#1565c0;border-color:#bbdefb}
.status-in_progress{background:#fff8e1;color:#f57f17;border-color:#ffecb3}
.status-completed{background:#e8f5e9;color:#2e7d32;border-color:#c8e6c9}
.status-archived{background:#eceff1;color:#546e7a;border-color:#cfd8dc}
.priority-normal{background:#eceff1;color:#455a64;border-color:#cfd8dc}
.priority-urgent{background:#fff3e0;color:#e65100;border-color:#ffe0b2}
.priority-very_urgent{background:#ffebee;color:#c62828;border-color:#ffcdd2}
.type-out{background:#e0f2f1;color:#00695c;border-color:#b2dfdb}
.type-in{background:#e8eaf6;color:#3949ab;border-color:#c5cae9}
.form-card{max-width:760px}
.form-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}
.form-group{margin-bottom:14px}
.form-group label,.login-card label{display:block;font-weight:600;margin-bottom:6px;font-size:14px}
input,select,textarea{width:100%;padding:9px 12px;font-family:inherit;font-size:14px;border:1px solid var(--border);border-radius:8px;background:#fff;color:var(--text)}
input:focus,select:focus,textarea:focus{outline:2px solid rgba(15,94,87,.25);border-color:var(--primary)}
.input-sm{padding:6px 9px;font-size:13px;margin-bottom:6px}
.form-actions{display:flex;gap:10px;margin-top:8px}
.ref-preview{background:#f0f7f6;border:1px dashed var(--primary);border-radius:8px;padding:9px 12px;font-weight:700;color:var(--primary);font-family:monospace;font-size:15px;text-align:left}
.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.filters input,.filters select{width:auto;min-width:140px}
.filters .grow{flex:1;min-width:200px}
.btn{display:inline-block;padding:9px 18px;border-radius:8px;border:1px solid transparent;font-family:inherit;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;text-align:center;transition:opacity .15s}
.btn:hover{opacity:.88}
.btn-primary{background:var(--primary);color:#fff}
.btn-danger{background:var(--danger);color:#fff}
.btn-light{background:#eef3f2;color:var(--text);border-color:var(--border)}
.btn-sm{padding:5px 12px;font-size:12.5px}
.btn-block{width:100%}
.alert{padding:12px 16px;border-radius:8px;margin-bottom:14px;font-weight:500}
.alert-success{background:#e8f5e9;color:#2e7d32;border:1px solid #c8e6c9}
.alert-danger{background:#ffebee;color:#c62828;border:1px solid #ffcdd2}
.login-body{background:linear-gradient(135deg,#0b4a44,#0f766e);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.login-wrap{display:flex;max-width:900px;width:100%;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.25)}
.login-side{flex:1;background:linear-gradient(180deg,#0b4a44,#0f5e57);color:#fff;padding:44px;display:flex;flex-direction:column;gap:26px}
.login-side .brand{border:none;padding:0}
.login-side h2{font-size:26px;line-height:1.5}
.login-side h2 span{color:#7fd9cd}
.features{list-style:none;display:flex;flex-direction:column;gap:12px;color:#d7ece9}
.login-card{flex:1;padding:44px}
.login-card h1{font-size:24px;margin-bottom:4px}
.login-card form{margin-top:20px;display:flex;flex-direction:column;gap:14px}
@media(max-width:760px){.login-side{display:none}}
.page-head{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:20px}
.page-actions{display:flex;gap:10px}
.muted{color:var(--muted)}
.small{font-size:12.5px}
.inline{display:inline}
.inline-flex{display:flex;gap:6px;align-items:center}
.inline-flex input{width:auto}
.progress-row{margin-bottom:14px}
.progress-head{display:flex;justify-content:space-between;margin-bottom:6px}
.progress{height:8px;background:#eef3f2;border-radius:6px;overflow:hidden}
.progress-bar{height:100%;background:var(--primary);border-radius:6px}
.pagination{display:flex;align-items:center;justify-content:space-between;padding-top:14px;border-top:1px solid var(--border);margin-top:6px}
.user-summary{display:flex;flex-wrap:wrap;gap:8px}
.dropdown{position:relative}
.dropdown summary{list-style:none;cursor:pointer}
.dropdown summary::-webkit-details-marker{display:none}
.dropdown-menu{position:absolute;left:0;top:100%;z-index:20;background:#fff;border:1px solid var(--border);border-radius:10px;padding:14px;width:250px;box-shadow:0 8px 24px rgba(0,0,0,.12)}
.dropdown-menu label{font-weight:600;margin:6px 0 3px;display:block}
.dropdown-menu hr{border:none;border-top:1px solid var(--border);margin:10px 0}
@media(max-width:860px){.sidebar{display:none}.content{padding:16px}}
</style>';
}

// ---------------- التخطيط العام ----------------
function layoutStart(string $title, string $active, array $user): void
{
    $nav = [
        ['dashboard', 'لوحة التحكم', '📊'],
        ['correspondence&type=outgoing', 'الصادر', '📤'],
        ['correspondence&type=incoming', 'الوارد', '📥'],
        ['reports', 'التقارير', '📋'],
    ];
    if ($user['role'] === 'admin') {
        $nav[] = ['departments', 'الإدارات', '🏢'];
        $nav[] = ['users', 'المستخدمون', '👥'];
        $nav[] = ['audit', 'سجل التدقيق', '🔍'];
    }
    ?>
<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= e($title) ?> — <?= e(APP_NAME) ?></title>
<?php printCss(); ?>
</head>
<body>
<div class="app">
    <aside class="sidebar">
        <div class="brand">
            <div class="brand-icon">✉️</div>
            <div>
                <div class="brand-name">الصادر والوارد</div>
                <div class="brand-sub">نظام متابعة المعاملات</div>
            </div>
        </div>
        <nav>
            <?php foreach ($nav as [$route, $label, $icon]): ?>
                <?php $routePage = strtok($route, '&'); ?>
                <a class="nav-link <?= $active === $routePage ? 'active' : '' ?>"
                   href="?page=<?= e($route) ?>">
                    <span class="nav-icon"><?= $icon ?></span><?= e($label) ?>
                </a>
            <?php endforeach; ?>
        </nav>
        <div class="sidebar-user">
            <div class="user-name"><?= e($user['name']) ?></div>
            <div class="user-meta">
                <?= e(ROLE_LABELS[$user['role']] ?? $user['role']) ?>
                <?= $user['dept_name'] ? ' — ' . e($user['dept_name']) : '' ?>
            </div>
        </div>
    </aside>

    <div class="main">
        <header class="topbar">
            <h1><?= e($title) ?></h1>
            <div class="topbar-actions">
                <a class="btn btn-light" href="?page=password">🔑 كلمة المرور</a>
                <a class="btn btn-danger" href="?page=logout">تسجيل الخروج</a>
            </div>
        </header>
        <main class="content">
            <?php renderFlash(); ?>
    <?php
}

function layoutEnd(): void
{
    ?>
        </main>
    </div>
</div>
</body>
</html>
    <?php
}

// ============================================================
// صفحة تسجيل الدخول
// ============================================================
function pageLogin(): void
{
    if (currentUser()) {
        header('Location: ?');
        exit;
    }
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        checkCsrf();
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        if ($username === '' || $password === '') {
            $error = 'يرجى إدخال اسم المستخدم وكلمة المرور';
        } elseif (attemptLogin($username, $password)) {
            header('Location: ?');
            exit;
        } else {
            $error = 'اسم المستخدم أو كلمة المرور غير صحيحة، أو الحساب موقوف';
        }
    }
    ?>
<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>تسجيل الدخول — <?= e(APP_NAME) ?></title>
<?php printCss(); ?>
</head>
<body class="login-body">
<div class="login-wrap">
    <div class="login-side">
        <div class="brand">
            <div class="brand-icon">✉️</div>
            <div>
                <div class="brand-name">الصادر والوارد</div>
                <div class="brand-sub">إدارة ومتابعة المعاملات</div>
            </div>
        </div>
        <h2>سجّل معاملاتك الصادرة والواردة<br><span>بأمان وموثوقية</span></h2>
        <ul class="features">
            <li>🔐 دخول آمن باسم مستخدم وكلمة مرور مشفرة</li>
            <li>🏢 ترقيم تسلسلي مستقل لكل إدارة</li>
            <li>🔍 سجل تدقيق يربط كل إجراء بمنفّذه</li>
        </ul>
    </div>
    <div class="login-card">
        <h1>تسجيل الدخول</h1>
        <p class="muted">أدخل بيانات حسابك للوصول إلى النظام</p>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= e($error) ?></div>
        <?php endif; ?>
        <form method="post" action="?page=login">
            <?= csrfField() ?>
            <label>اسم المستخدم</label>
            <input type="text" name="username" dir="ltr" autocomplete="username" required autofocus>
            <label>كلمة المرور</label>
            <input type="password" name="password" dir="ltr" autocomplete="current-password" required>
            <button type="submit" class="btn btn-primary btn-block">دخول</button>
        </form>
        <p class="muted small">في حال فقدان بيانات الدخول، تواصل مع مدير النظام</p>
    </div>
</div>
</body>
</html>
    <?php
}

// ============================================================
// لوحة التحكم
// ============================================================
function pageDashboard(array $user): void
{
    $pdo = db();
    $isAdmin = $user['role'] === 'admin';
    $deptFilter = $isAdmin ? '' : ' AND c.dept_id = ' . (int) $user['dept_id'];

    $stats = [
        'outgoing' => (int) $pdo->query("SELECT COUNT(*) FROM correspondence c WHERE c.type='outgoing'" . $deptFilter)->fetchColumn(),
        'incoming' => (int) $pdo->query("SELECT COUNT(*) FROM correspondence c WHERE c.type='incoming'" . $deptFilter)->fetchColumn(),
        'today'    => (int) $pdo->query("SELECT COUNT(*) FROM correspondence c WHERE c.cdate = date('now','localtime')" . $deptFilter)->fetchColumn(),
    ];
    $byStatus = $pdo->query("SELECT status, COUNT(*) AS n FROM correspondence c WHERE 1=1" . $deptFilter . " GROUP BY status")
        ->fetchAll(PDO::FETCH_KEY_PAIR);
    $recent = $pdo->query(
        "SELECT c.*, u.name AS creator_name, d.name AS dept_name
         FROM correspondence c
         JOIN users u ON u.id = c.created_by
         JOIN departments d ON d.id = c.dept_id
         WHERE 1=1" . $deptFilter . " ORDER BY c.created_at DESC, c.id DESC LIMIT 10"
    )->fetchAll();
    $deptStats = $isAdmin ? $pdo->query(
        "SELECT d.name, d.code,
                SUM(CASE WHEN c.type='outgoing' THEN 1 ELSE 0 END) AS outgoing,
                SUM(CASE WHEN c.type='incoming' THEN 1 ELSE 0 END) AS incoming
         FROM departments d LEFT JOIN correspondence c ON c.dept_id = d.id
         GROUP BY d.id ORDER BY d.id"
    )->fetchAll() : [];

    layoutStart('لوحة التحكم', 'dashboard', $user);
    ?>
<div class="cards">
    <div class="card stat"><div class="stat-icon bg-slate">🗂️</div>
        <div><div class="stat-num"><?= $stats['outgoing'] + $stats['incoming'] ?></div><div class="stat-label">إجمالي المعاملات</div></div></div>
    <div class="card stat"><div class="stat-icon bg-teal">📤</div>
        <div><div class="stat-num"><?= $stats['outgoing'] ?></div><div class="stat-label">الصادر</div></div></div>
    <div class="card stat"><div class="stat-icon bg-indigo">📥</div>
        <div><div class="stat-num"><?= $stats['incoming'] ?></div><div class="stat-label">الوارد</div></div></div>
    <div class="card stat"><div class="stat-icon bg-amber">📅</div>
        <div><div class="stat-num"><?= $stats['today'] ?></div><div class="stat-label">معاملات اليوم</div></div></div>
</div>

<div class="grid-2">
    <div class="card">
        <h3 class="card-title">المعاملات حسب الحالة</h3>
        <?php
        $total = max(1, $stats['outgoing'] + $stats['incoming']);
        foreach (STATUS_LABELS as $key => $label):
            $n = (int) ($byStatus[$key] ?? 0);
            $pct = round($n / $total * 100);
        ?>
        <div class="progress-row">
            <div class="progress-head"><?= statusBadge($key) ?><b><?= $n ?></b></div>
            <div class="progress"><div class="progress-bar" style="width:<?= $pct ?>%"></div></div>
        </div>
        <?php endforeach; ?>
    </div>
    <?php if ($isAdmin && $deptStats): ?>
    <div class="card">
        <h3 class="card-title">المعاملات حسب الإدارة</h3>
        <table class="table">
            <thead><tr><th>الإدارة</th><th>الكود</th><th>صادر</th><th>وارد</th></tr></thead>
            <tbody>
            <?php foreach ($deptStats as $d): ?>
                <tr><td><?= e($d['name']) ?></td><td><code dir="ltr"><?= e($d['code']) ?></code></td>
                    <td><?= (int) $d['outgoing'] ?></td><td><?= (int) $d['incoming'] ?></td></tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<div class="card">
    <h3 class="card-title">أحدث المعاملات المسجلة</h3>
    <div class="table-wrap">
    <table class="table">
        <thead><tr><th>الرقم المرجعي</th><th>النوع</th><th>الإدارة</th><th>الموضوع</th><th>الجهة</th><th>التاريخ</th><th>الحالة</th><th>سجّلها</th></tr></thead>
        <tbody>
        <?php foreach ($recent as $r): ?>
            <tr>
                <td><code dir="ltr"><?= e($r['ref_number']) ?></code></td>
                <td><?= typeBadge($r['type']) ?></td>
                <td><?= e($r['dept_name']) ?></td>
                <td class="truncate"><?= e($r['subject']) ?></td>
                <td class="truncate"><?= e($r['entity']) ?></td>
                <td><?= e($r['cdate']) ?></td>
                <td><?= statusBadge($r['status']) ?></td>
                <td><?= e($r['creator_name']) ?></td>
            </tr>
        <?php endforeach; ?>
        <?php if (!$recent): ?>
            <tr><td colspan="8" class="empty">لا توجد معاملات مسجلة بعد — ابدأ من قسم الصادر أو الوارد</td></tr>
        <?php endif; ?>
        </tbody>
    </table>
    </div>
</div>
    <?php
    layoutEnd();
}

// ============================================================
// سجل الصادر / الوارد
// ============================================================
function pageCorrespondence(array $user): void
{
    $pdo = db();
    $type = ($_GET['type'] ?? 'outgoing') === 'incoming' ? 'incoming' : 'outgoing';
    $isAdmin = $user['role'] === 'admin';

    $q        = trim((string) ($_GET['q'] ?? ''));
    $status   = (string) ($_GET['status'] ?? '');
    $deptId   = (int) ($_GET['dept'] ?? 0);
    $from     = (string) ($_GET['from'] ?? '');
    $to       = (string) ($_GET['to'] ?? '');
    $pageNum  = max(1, (int) ($_GET['p'] ?? 1));
    $pageSize = 15;

    $where  = ['c.type = ?'];
    $params = [$type];
    if (!$isAdmin) {
        if (!$user['dept_id']) {
            exit('حسابك غير مرتبط بأي إدارة — تواصل مع مدير النظام');
        }
        $where[] = 'c.dept_id = ?';
        $params[] = (int) $user['dept_id'];
    } elseif ($deptId > 0) {
        $where[] = 'c.dept_id = ?';
        $params[] = $deptId;
    }
    if ($status !== '' && isset(STATUS_LABELS[$status])) {
        $where[] = 'c.status = ?';
        $params[] = $status;
    }
    if ($q !== '') {
        $where[] = '(c.subject LIKE ? OR c.entity LIKE ? OR c.ref_number LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like);
    }
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $from)) { $where[] = 'c.cdate >= ?'; $params[] = $from; }
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $to))   { $where[] = 'c.cdate <= ?'; $params[] = $to; }
    $whereSql = implode(' AND ', $where);

    $baseSql = "FROM correspondence c
        JOIN users u ON u.id = c.created_by
        LEFT JOIN users u2 ON u2.id = c.updated_by
        JOIN departments d ON d.id = c.dept_id
        WHERE $whereSql";

    $stmt = $pdo->prepare("SELECT COUNT(*) $baseSql");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    if (isset($_GET['export'])) {
        $stmt = $pdo->prepare("SELECT c.*, u.name AS creator_name, u2.name AS updater_name, d.name AS dept_name $baseSql ORDER BY c.cdate DESC, c.id DESC");
        $stmt->execute($params);
        $rows = [];
        foreach ($stmt->fetchAll() as $r) {
            $rows[] = [
                $r['ref_number'], TYPE_LABELS[$r['type']], $r['dept_name'],
                $r['subject'], $r['entity'], $r['cdate'],
                STATUS_LABELS[$r['status']], PRIORITY_LABELS[$r['priority']],
                $r['creator_name'], $r['created_at'],
                $r['updater_name'] ?? '', $r['updated_at'] ?? '',
                preg_replace('/\s+/', ' ', (string) $r['notes']),
            ];
        }
        audit((int) $user['id'], $user['username'], 'تصدير سجل', 'تصدير ' . TYPE_LABELS[$type] . " ($total معاملة)");
        exportCsv(
            $type === 'outgoing' ? 'outgoing.csv' : 'incoming.csv',
            ['الرقم المرجعي', 'النوع', 'الإدارة', 'الموضوع', 'الجهة', 'التاريخ', 'الحالة', 'الأولوية', 'سجّلها', 'تاريخ التسجيل', 'عدّلها', 'تاريخ التعديل', 'ملاحظات'],
            $rows
        );
    }

    $totalPages = max(1, (int) ceil($total / $pageSize));
    $pageNum = min($pageNum, $totalPages);
    $stmt = $pdo->prepare(
        "SELECT c.*, u.name AS creator_name, d.name AS dept_name $baseSql
         ORDER BY c.cdate DESC, c.id DESC LIMIT $pageSize OFFSET " . (($pageNum - 1) * $pageSize)
    );
    $stmt->execute($params);
    $items = $stmt->fetchAll();
    $departments = $isAdmin ? allowedDepartments($user) : [];

    $qs = fn(array $extra = []) => '?' . http_build_query(array_merge([
        'page' => 'correspondence', 'type' => $type, 'q' => $q,
        'status' => $status, 'dept' => $deptId, 'from' => $from, 'to' => $to,
    ], $extra));

    $typeLabel = TYPE_LABELS[$type];
    layoutStart("سجل $typeLabel", 'correspondence', $user);
    ?>
<div class="page-head">
    <div>
        <h2 class="page-title">سجل <?= e($typeLabel) ?></h2>
        <p class="muted"><?= $total ?> معاملة مسجلة</p>
    </div>
    <div class="page-actions">
        <a class="btn btn-light" href="<?= e($qs(['export' => 1])) ?>">⬇️ تصدير CSV</a>
        <a class="btn btn-primary" href="?page=corr_form&type=<?= $type ?>">＋ تسجيل معاملة <?= e($typeLabel) ?></a>
    </div>
</div>

<div class="card">
    <form class="filters" method="get" action="">
        <input type="hidden" name="page" value="correspondence">
        <input type="hidden" name="type" value="<?= e($type) ?>">
        <input type="text" name="q" value="<?= e($q) ?>" placeholder="بحث بالموضوع أو الجهة أو الرقم المرجعي..." class="grow">
        <?php if ($isAdmin): ?>
        <select name="dept">
            <option value="0">كل الإدارات</option>
            <?php foreach ($departments as $d): ?>
                <option value="<?= (int) $d['id'] ?>" <?= $deptId === (int) $d['id'] ? 'selected' : '' ?>><?= e($d['name']) ?></option>
            <?php endforeach; ?>
        </select>
        <?php endif; ?>
        <select name="status">
            <option value="">كل الحالات</option>
            <?php foreach (STATUS_LABELS as $k => $v): ?>
                <option value="<?= e($k) ?>" <?= $status === $k ? 'selected' : '' ?>><?= e($v) ?></option>
            <?php endforeach; ?>
        </select>
        <input type="date" name="from" value="<?= e($from) ?>" title="من تاريخ">
        <input type="date" name="to" value="<?= e($to) ?>" title="إلى تاريخ">
        <button class="btn btn-primary" type="submit">بحث</button>
        <a class="btn btn-light" href="?page=correspondence&type=<?= $type ?>">إعادة تعيين</a>
    </form>
</div>

<div class="card">
    <div class="table-wrap">
    <table class="table">
        <thead>
            <tr>
                <th>الرقم المرجعي</th>
                <?php if ($isAdmin): ?><th>الإدارة</th><?php endif; ?>
                <th>الموضوع</th><th>الجهة</th><th>التاريخ</th>
                <th>الحالة</th><th>الأولوية</th><th>سجّلها</th><th>إجراءات</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($items as $r): ?>
            <tr>
                <td><code dir="ltr"><?= e($r['ref_number']) ?></code></td>
                <?php if ($isAdmin): ?><td><?= e($r['dept_name']) ?></td><?php endif; ?>
                <td class="truncate" title="<?= e($r['subject']) ?>"><?= e($r['subject']) ?></td>
                <td class="truncate"><?= e($r['entity']) ?></td>
                <td><?= e($r['cdate']) ?></td>
                <td><?= statusBadge($r['status']) ?></td>
                <td><?= priorityBadge($r['priority']) ?></td>
                <td><?= e($r['creator_name']) ?></td>
                <td class="actions">
                    <?php if (canModifyRecord($user, $r)): ?>
                        <a class="btn btn-sm btn-light" href="?page=corr_form&id=<?= (int) $r['id'] ?>">✏️ تعديل</a>
                        <form method="post" action="?page=corr_delete" class="inline"
                              onsubmit="return confirm('هل أنت متأكد من حذف هذه المعاملة؟')">
                            <?= csrfField() ?>
                            <input type="hidden" name="id" value="<?= (int) $r['id'] ?>">
                            <input type="hidden" name="type" value="<?= e($type) ?>">
                            <button class="btn btn-sm btn-danger" type="submit">🗑️ حذف</button>
                        </form>
                    <?php else: ?>
                        <span class="muted small">—</span>
                    <?php endif; ?>
                </td>
            </tr>
        <?php endforeach; ?>
        <?php if (!$items): ?>
            <tr><td colspan="9" class="empty">لا توجد معاملات مطابقة</td></tr>
        <?php endif; ?>
        </tbody>
    </table>
    </div>

    <?php if ($totalPages > 1): ?>
    <div class="pagination">
        <span class="muted">صفحة <?= $pageNum ?> من <?= $totalPages ?></span>
        <?php if ($pageNum > 1): ?>
            <a class="btn btn-sm btn-light" href="<?= e($qs(['p' => $pageNum - 1])) ?>">السابق</a>
        <?php endif; ?>
        <?php if ($pageNum < $totalPages): ?>
            <a class="btn btn-sm btn-light" href="<?= e($qs(['p' => $pageNum + 1])) ?>">التالي</a>
        <?php endif; ?>
    </div>
    <?php endif; ?>
</div>
    <?php
    layoutEnd();
}

// ============================================================
// تسجيل / تعديل معاملة — ترقيم تسلسلي مستقل لكل إدارة
// ============================================================
function pageCorrForm(array $user): void
{
    $pdo     = db();
    $id      = (int) ($_GET['id'] ?? 0);
    $isAdmin = $user['role'] === 'admin';
    $editing = null;

    if ($id > 0) {
        $stmt = $pdo->prepare('SELECT * FROM correspondence WHERE id = ?');
        $stmt->execute([$id]);
        $editing = $stmt->fetch() ?: null;
        if (!$editing || !canModifyRecord($user, $editing)) {
            http_response_code(403);
            exit('لا يمكن تعديل هذه المعاملة إلا من مُسجّلها أو مدير النظام');
        }
    }

    $type = $editing['type'] ?? ((($_GET['type'] ?? 'outgoing') === 'incoming') ? 'incoming' : 'outgoing');
    $departments = allowedDepartments($user);
    if (!$departments) {
        exit('حسابك غير مرتبط بأي إدارة — تواصل مع مدير النظام');
    }

    $errors = [];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        checkCsrf();
        $deptId  = (int) ($_POST['dept_id'] ?? 0);
        $subject = trim((string) ($_POST['subject'] ?? ''));
        $entity  = trim((string) ($_POST['entity'] ?? ''));
        $cdate   = (string) ($_POST['cdate'] ?? '');
        $status  = (string) ($_POST['status'] ?? 'new');
        $priority = (string) ($_POST['priority'] ?? 'normal');
        $notes   = trim((string) ($_POST['notes'] ?? ''));

        if (!$editing && !canAccessDept($user, $deptId)) {
            $errors[] = 'لا يمكنك التسجيل لإدارة غير إدارتك';
        }
        if ($editing) {
            $deptId = (int) $editing['dept_id'];
        }
        if ($subject === '') $errors[] = 'الموضوع مطلوب';
        if ($entity === '')  $errors[] = 'الجهة مطلوبة';
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $cdate)) $errors[] = 'التاريخ غير صحيح';
        if (!isset(STATUS_LABELS[$status])) $status = 'new';
        if (!isset(PRIORITY_LABELS[$priority])) $priority = 'normal';

        if (!$errors) {
            if ($editing) {
                $pdo->prepare(
                    "UPDATE correspondence SET subject=?, entity=?, cdate=?, status=?, priority=?, notes=?,
                     updated_by=?, updated_at=datetime('now','localtime') WHERE id=?"
                )->execute([$subject, $entity, $cdate, $status, $priority, $notes ?: null, $user['id'], $editing['id']]);
                audit((int) $user['id'], $user['username'], 'تعديل معاملة', "تعديل {$editing['ref_number']} — $subject");
                flash('success', 'تم تحديث المعاملة بنجاح');
            } else {
                $pdo->exec('BEGIN IMMEDIATE');
                try {
                    $dept = $pdo->prepare('SELECT code FROM departments WHERE id = ? AND is_active = 1');
                    $dept->execute([$deptId]);
                    $code = $dept->fetchColumn();
                    if (!$code) {
                        throw new RuntimeException('الإدارة غير موجودة أو موقوفة');
                    }
                    $year  = (int) date('Y');
                    $tCode = $type === 'outgoing' ? 'OUT' : 'IN';
                    $s = $pdo->prepare('SELECT COALESCE(MAX(serial),0)+1 FROM correspondence WHERE dept_id=? AND type=? AND year=?');
                    $s->execute([$deptId, $type, $year]);
                    $serial = (int) $s->fetchColumn();
                    $ref = sprintf('%s-%s-%d-%04d', $code, $tCode, $year, $serial);

                    $pdo->prepare(
                        'INSERT INTO correspondence
                         (dept_id, type, year, serial, ref_number, subject, entity, cdate, status, priority, notes, created_by)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
                    )->execute([$deptId, $type, $year, $serial, $ref, $subject, $entity, $cdate, $status, $priority, $notes ?: null, $user['id']]);

                    audit((int) $user['id'], $user['username'], 'تسجيل معاملة ' . TYPE_LABELS[$type], "تسجيل $ref — $subject");
                    $pdo->exec('COMMIT');
                    flash('success', "تم تسجيل المعاملة برقم مرجعي $ref");
                } catch (Throwable $ex) {
                    $pdo->exec('ROLLBACK');
                    $errors[] = 'تعذر حفظ المعاملة، حاول مرة أخرى';
                }
            }
            if (!$errors) {
                header('Location: ?page=correspondence&type=' . $type);
                exit;
            }
        }

        if ($errors && !$id) {
            $editing = ['dept_id' => $deptId, 'subject' => $subject, 'entity' => $entity,
                'cdate' => $cdate, 'status' => $status, 'priority' => $priority, 'notes' => $notes];
        }
    }

    // خريطة معاينة الأرقام المرجعية لكل إدارة (JavaScript)
    $refMap = [];
    if (!$editing) {
        foreach ($departments as $d) {
            $refMap[(int) $d['id']] = peekNextRef((int) $d['id'], $type);
        }
    }

    $v = fn(string $key, string $default = '') => e((string) ($editing[$key] ?? $default));
    $typeLabel = TYPE_LABELS[$type];
    layoutStart(($editing && $id ? 'تعديل معاملة' : "تسجيل معاملة $typeLabel"), 'correspondence', $user);
    ?>
<div class="card form-card">
    <h3 class="card-title">
        <?= $editing && $id ? 'تعديل المعاملة <code dir="ltr">' . e($editing['ref_number']) . '</code>' : "تسجيل معاملة $typeLabel جديدة" ?>
    </h3>
    <?php foreach ($errors as $err): ?>
        <div class="alert alert-danger"><?= e($err) ?></div>
    <?php endforeach; ?>

    <form method="post">
        <?= csrfField() ?>
        <?php if (!($editing && $id)): ?>
        <div class="form-row">
            <div class="form-group">
                <label>الإدارة *</label>
                <select name="dept_id" required onchange="document.getElementById('refPreview').textContent = refMap[this.value] || ''">
                    <?php foreach ($departments as $d): ?>
                        <option value="<?= (int) $d['id'] ?>" <?= (int) ($editing['dept_id'] ?? $departments[0]['id']) === (int) $d['id'] ? 'selected' : '' ?>>
                            <?= e($d['name']) ?> (<?= e($d['code']) ?>)
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label>الرقم المرجعي التلقائي</label>
                <div class="ref-preview" dir="ltr" id="refPreview"><?= e($refMap[(int) ($editing['dept_id'] ?? $departments[0]['id'])] ?? '') ?></div>
                <small class="muted">كود الإدارة ← النوع ← السنة ← التسلسل</small>
            </div>
        </div>
        <script>var refMap = <?= json_encode($refMap, JSON_UNESCAPED_UNICODE) ?>;</script>
        <?php endif; ?>

        <div class="form-group">
            <label>الموضوع *</label>
            <input type="text" name="subject" value="<?= $v('subject') ?>" required maxlength="500">
        </div>
        <div class="form-group">
            <label><?= $type === 'outgoing' ? 'الجهة المُرسل إليها' : 'الجهة الواردة منها' ?> *</label>
            <input type="text" name="entity" value="<?= $v('entity') ?>" required maxlength="255">
        </div>
        <div class="form-row">
            <div class="form-group">
                <label>التاريخ *</label>
                <input type="date" name="cdate" value="<?= $v('cdate', date('Y-m-d')) ?>" required>
            </div>
            <div class="form-group">
                <label>الحالة</label>
                <select name="status">
                    <?php foreach (STATUS_LABELS as $k => $lbl): ?>
                        <option value="<?= e($k) ?>" <?= ($editing['status'] ?? 'new') === $k ? 'selected' : '' ?>><?= e($lbl) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label>الأولوية</label>
                <select name="priority">
                    <?php foreach (PRIORITY_LABELS as $k => $lbl): ?>
                        <option value="<?= e($k) ?>" <?= ($editing['priority'] ?? 'normal') === $k ? 'selected' : '' ?>><?= e($lbl) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>
        <div class="form-group">
            <label>ملاحظات</label>
            <textarea name="notes" rows="3" maxlength="5000"><?= $v('notes') ?></textarea>
        </div>
        <div class="form-actions">
            <button type="submit" class="btn btn-primary"><?= $editing && $id ? 'حفظ التعديلات' : 'تسجيل المعاملة' ?></button>
            <a class="btn btn-light" href="?page=correspondence&type=<?= $type ?>">إلغاء</a>
        </div>
    </form>
</div>
    <?php
    layoutEnd();
}

// ============================================================
// حذف معاملة
// ============================================================
function pageCorrDelete(array $user): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit('طريقة غير مسموحة');
    }
    checkCsrf();
    $pdo  = db();
    $id   = (int) ($_POST['id'] ?? 0);
    $type = ($_POST['type'] ?? 'outgoing') === 'incoming' ? 'incoming' : 'outgoing';

    $stmt = $pdo->prepare('SELECT * FROM correspondence WHERE id = ?');
    $stmt->execute([$id]);
    $record = $stmt->fetch();
    if (!$record || !canModifyRecord($user, $record)) {
        flash('danger', 'لا يمكن حذف هذه المعاملة إلا من مُسجّلها أو مدير النظام');
        header('Location: ?page=correspondence&type=' . $type);
        exit;
    }
    $pdo->prepare('DELETE FROM correspondence WHERE id = ?')->execute([$id]);
    audit((int) $user['id'], $user['username'], 'حذف معاملة', "حذف {$record['ref_number']} — {$record['subject']}");
    flash('success', 'تم حذف المعاملة ' . $record['ref_number']);
    header('Location: ?page=correspondence&type=' . $type);
    exit;
}

// ============================================================
// إدارة الإدارات (للمدير)
// ============================================================
function pageDepartments(array $user): void
{
    requireAdmin($user);
    $pdo = db();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        checkCsrf();
        $action = (string) ($_POST['action'] ?? '');
        if ($action === 'create') {
            $name = trim((string) ($_POST['name'] ?? ''));
            $code = strtoupper(trim((string) ($_POST['code'] ?? '')));
            if ($name === '' || !preg_match('/^[A-Z0-9]{2,10}$/', $code)) {
                flash('danger', 'اسم الإدارة مطلوب، والكود 2-10 أحرف إنجليزية أو أرقام');
            } else {
                try {
                    $pdo->prepare('INSERT INTO departments (name, code) VALUES (?, ?)')->execute([$name, $code]);
                    audit((int) $user['id'], $user['username'], 'إضافة إدارة', "$name ($code)");
                    flash('success', 'تمت إضافة الإدارة بنجاح');
                } catch (Throwable $e) {
                    flash('danger', 'الكود مستخدم من قبل لإدارة أخرى');
                }
            }
        } elseif ($action === 'toggle') {
            $deptId = (int) ($_POST['id'] ?? 0);
            $pdo->prepare('UPDATE departments SET is_active = 1 - is_active WHERE id = ?')->execute([$deptId]);
            audit((int) $user['id'], $user['username'], 'تفعيل/إيقاف إدارة', "الإدارة رقم $deptId");
            flash('success', 'تم تحديث حالة الإدارة');
        } elseif ($action === 'rename') {
            $deptId = (int) ($_POST['id'] ?? 0);
            $name = trim((string) ($_POST['name'] ?? ''));
            if ($name !== '') {
                $pdo->prepare('UPDATE departments SET name = ? WHERE id = ?')->execute([$name, $deptId]);
                audit((int) $user['id'], $user['username'], 'تعديل اسم إدارة', $name);
                flash('success', 'تم تحديث اسم الإدارة');
            }
        }
        header('Location: ?page=departments');
        exit;
    }

    $departments = $pdo->query(
        'SELECT d.*,
            (SELECT COUNT(*) FROM correspondence c WHERE c.dept_id = d.id) AS total,
            (SELECT COUNT(*) FROM users u WHERE u.dept_id = d.id) AS users_count
         FROM departments d ORDER BY d.id'
    )->fetchAll();

    layoutStart('إدارة الإدارات', 'departments', $user);
    ?>
<div class="page-head">
    <div>
        <h2 class="page-title">الإدارات</h2>
        <p class="muted">كل إدارة لها كود خاص يبدأ به تسلسل أرقام الصادر والوارد الخاصة بها</p>
    </div>
</div>
<div class="grid-2">
    <div class="card">
        <h3 class="card-title">الإدارات المسجلة</h3>
        <div class="table-wrap">
        <table class="table">
            <thead><tr><th>الإدارة</th><th>الكود</th><th>مثال الترقيم</th><th>المعاملات</th><th>الموظفون</th><th>الحالة</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($departments as $d): ?>
                <tr>
                    <td>
                        <form method="post" class="inline-flex">
                            <?= csrfField() ?>
                            <input type="hidden" name="action" value="rename">
                            <input type="hidden" name="id" value="<?= (int) $d['id'] ?>">
                            <input type="text" name="name" value="<?= e($d['name']) ?>" class="input-sm">
                            <button class="btn btn-sm btn-light" type="submit">حفظ</button>
                        </form>
                    </td>
                    <td><code dir="ltr" class="dept-code"><?= e($d['code']) ?></code></td>
                    <td><code dir="ltr" class="muted small"><?= e($d['code']) ?>-OUT-<?= date('Y') ?>-0001</code></td>
                    <td><?= (int) $d['total'] ?></td>
                    <td><?= (int) $d['users_count'] ?></td>
                    <td><span class="badge <?= $d['is_active'] ? 'status-completed' : 'status-archived' ?>"><?= $d['is_active'] ? 'نشطة' : 'موقوفة' ?></span></td>
                    <td>
                        <form method="post" class="inline">
                            <?= csrfField() ?>
                            <input type="hidden" name="action" value="toggle">
                            <input type="hidden" name="id" value="<?= (int) $d['id'] ?>">
                            <button class="btn btn-sm <?= $d['is_active'] ? 'btn-danger' : 'btn-primary' ?>" type="submit">
                                <?= $d['is_active'] ? 'إيقاف' : 'تفعيل' ?>
                            </button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
        <p class="muted small">ملاحظة: الكود لا يتغير بعد الاستخدام حفاظًا على سلامة الأرقام المرجعية.</p>
    </div>
    <div class="card form-card">
        <h3 class="card-title">إضافة إدارة جديدة</h3>
        <form method="post">
            <?= csrfField() ?>
            <input type="hidden" name="action" value="create">
            <div class="form-group">
                <label>اسم الإدارة *</label>
                <input type="text" name="name" required maxlength="255" placeholder="مثال: إدارة الشؤون القانونية">
            </div>
            <div class="form-group">
                <label>الكود * (أحرف إنجليزية أو أرقام، 2-10 خانات)</label>
                <input type="text" name="code" required dir="ltr" maxlength="10" pattern="[A-Za-z0-9]{2,10}"
                       placeholder="مثال: LEG" style="text-transform:uppercase">
                <small class="muted">سيظهر في بداية كل رقم مرجعي: LEG-OUT-<?= date('Y') ?>-0001</small>
            </div>
            <button type="submit" class="btn btn-primary">إضافة الإدارة</button>
        </form>
    </div>
</div>
    <?php
    layoutEnd();
}

// ============================================================
// إدارة المستخدمين (للمدير)
// ============================================================
function pageUsers(array $user): void
{
    requireAdmin($user);
    $pdo = db();
    $departments = $pdo->query('SELECT * FROM departments WHERE is_active = 1 ORDER BY id')->fetchAll();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        checkCsrf();
        $action = (string) ($_POST['action'] ?? '');
        $targetId = (int) ($_POST['id'] ?? 0);

        if ($action === 'create') {
            $username = trim((string) ($_POST['username'] ?? ''));
            $name     = trim((string) ($_POST['name'] ?? ''));
            $password = (string) ($_POST['password'] ?? '');
            $role     = ($_POST['role'] ?? 'employee') === 'admin' ? 'admin' : 'employee';
            $deptId   = (int) ($_POST['dept_id'] ?? 0) ?: null;

            if (!preg_match('/^[a-zA-Z0-9._-]{3,50}$/', $username)) {
                flash('danger', 'اسم المستخدم: 3 أحرف إنجليزية أو أرقام على الأقل (بدون مسافات)');
            } elseif ($name === '') {
                flash('danger', 'اسم الموظف مطلوب');
            } elseif (strlen($password) < 8) {
                flash('danger', 'كلمة المرور يجب ألا تقل عن 8 أحرف');
            } else {
                $exists = $pdo->prepare('SELECT 1 FROM users WHERE username = ?');
                $exists->execute([$username]);
                if ($exists->fetchColumn()) {
                    flash('danger', 'اسم المستخدم مستخدم من قبل');
                } else {
                    $pdo->prepare('INSERT INTO users (username, password_hash, name, role, dept_id) VALUES (?,?,?,?,?)')
                        ->execute([$username, password_hash($password, PASSWORD_BCRYPT), $name, $role, $deptId]);
                    audit((int) $user['id'], $user['username'], 'إنشاء حساب مستخدم', "$name ($username)");
                    flash('success', 'تم إنشاء حساب الموظف بنجاح');
                }
            }
        } elseif ($targetId === (int) $user['id'] && in_array($action, ['toggle', 'delete'], true)) {
            flash('danger', 'لا يمكنك إيقاف أو حذف حسابك الخاص');
        } elseif ($action === 'toggle') {
            $pdo->prepare('UPDATE users SET is_active = 1 - is_active WHERE id = ?')->execute([$targetId]);
            audit((int) $user['id'], $user['username'], 'تفعيل/إيقاف حساب', "المستخدم رقم $targetId");
            flash('success', 'تم تحديث حالة الحساب');
        } elseif ($action === 'reset_password') {
            $password = (string) ($_POST['password'] ?? '');
            if (strlen($password) < 8) {
                flash('danger', 'كلمة المرور يجب ألا تقل عن 8 أحرف');
            } else {
                $pdo->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
                    ->execute([password_hash($password, PASSWORD_BCRYPT), $targetId]);
                audit((int) $user['id'], $user['username'], 'إعادة تعيين كلمة مرور', "المستخدم رقم $targetId");
                flash('success', 'تمت إعادة تعيين كلمة المرور');
            }
        } elseif ($action === 'update') {
            $name   = trim((string) ($_POST['name'] ?? ''));
            $role   = ($_POST['role'] ?? 'employee') === 'admin' ? 'admin' : 'employee';
            $deptId = (int) ($_POST['dept_id'] ?? 0) ?: null;
            if ($targetId === (int) $user['id'] && $role !== 'admin') {
                flash('danger', 'لا يمكنك إزالة صلاحية المدير عن حسابك الخاص');
            } elseif ($name !== '') {
                $pdo->prepare('UPDATE users SET name = ?, role = ?, dept_id = ? WHERE id = ?')
                    ->execute([$name, $role, $deptId, $targetId]);
                audit((int) $user['id'], $user['username'], 'تعديل بيانات مستخدم', "المستخدم رقم $targetId: $name");
                flash('success', 'تم تحديث بيانات المستخدم');
            }
        } elseif ($action === 'delete') {
            $target = $pdo->prepare('SELECT username, name FROM users WHERE id = ?');
            $target->execute([$targetId]);
            $t = $target->fetch();
            if ($t) {
                $pdo->prepare('DELETE FROM users WHERE id = ?')->execute([$targetId]);
                audit((int) $user['id'], $user['username'], 'حذف حساب مستخدم', "{$t['name']} ({$t['username']})");
                flash('success', 'تم حذف الحساب');
            }
        }
        header('Location: ?page=users');
        exit;
    }

    $users = $pdo->query(
        'SELECT u.*, d.name AS dept_name,
            (SELECT COUNT(*) FROM correspondence c WHERE c.created_by = u.id) AS records_count,
            (SELECT COUNT(*) FROM audit_log a WHERE a.user_id = u.id) AS actions_count
         FROM users u LEFT JOIN departments d ON d.id = u.dept_id ORDER BY u.id'
    )->fetchAll();

    layoutStart('إدارة المستخدمين', 'users', $user);
    ?>
<div class="page-head">
    <div>
        <h2 class="page-title">المستخدمون</h2>
        <p class="muted"><?= count($users) ?> حساب مسجل — كل مستخدم مرتبط بكل ما قام به في سجل التدقيق</p>
    </div>
</div>
<div class="card">
    <div class="table-wrap">
    <table class="table">
        <thead>
            <tr><th>الاسم</th><th>اسم المستخدم</th><th>الصلاحية</th><th>الإدارة</th>
                <th>معاملاته</th><th>إجراءاته</th><th>آخر دخول</th><th>الحالة</th><th></th></tr>
        </thead>
        <tbody>
        <?php foreach ($users as $u): ?>
            <tr>
                <td><?= e($u['name']) ?><?= (int) $u['id'] === (int) $user['id'] ? ' <span class="muted small">(أنت)</span>' : '' ?></td>
                <td><code dir="ltr"><?= e($u['username']) ?></code></td>
                <td><span class="badge <?= $u['role'] === 'admin' ? 'type-in' : 'status-new' ?>"><?= e(ROLE_LABELS[$u['role']]) ?></span></td>
                <td><?= e($u['dept_name'] ?? '—') ?></td>
                <td><?= (int) $u['records_count'] ?></td>
                <td><a href="?page=audit&user_id=<?= (int) $u['id'] ?>" title="عرض سجل إجراءاته"><?= (int) $u['actions_count'] ?></a></td>
                <td class="small"><?= e($u['last_login'] ?? 'لم يدخل بعد') ?></td>
                <td><span class="badge <?= $u['is_active'] ? 'status-completed' : 'status-archived' ?>"><?= $u['is_active'] ? 'نشط' : 'موقوف' ?></span></td>
                <td class="actions">
                    <details class="dropdown">
                        <summary class="btn btn-sm btn-light">إجراءات ▾</summary>
                        <div class="dropdown-menu">
                            <form method="post">
                                <?= csrfField() ?>
                                <input type="hidden" name="action" value="update">
                                <input type="hidden" name="id" value="<?= (int) $u['id'] ?>">
                                <label class="small">الاسم</label>
                                <input type="text" name="name" value="<?= e($u['name']) ?>" class="input-sm" required>
                                <label class="small">الصلاحية</label>
                                <select name="role" class="input-sm">
                                    <option value="employee" <?= $u['role'] === 'employee' ? 'selected' : '' ?>>موظف</option>
                                    <option value="admin" <?= $u['role'] === 'admin' ? 'selected' : '' ?>>مدير النظام</option>
                                </select>
                                <label class="small">الإدارة</label>
                                <select name="dept_id" class="input-sm">
                                    <option value="0">بدون إدارة</option>
                                    <?php foreach ($departments as $d): ?>
                                        <option value="<?= (int) $d['id'] ?>" <?= (int) $u['dept_id'] === (int) $d['id'] ? 'selected' : '' ?>><?= e($d['name']) ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <button class="btn btn-sm btn-primary btn-block" type="submit">حفظ التعديلات</button>
                            </form>
                            <hr>
                            <form method="post">
                                <?= csrfField() ?>
                                <input type="hidden" name="action" value="reset_password">
                                <input type="hidden" name="id" value="<?= (int) $u['id'] ?>">
                                <label class="small">كلمة مرور جديدة (8+ أحرف)</label>
                                <input type="password" name="password" class="input-sm" minlength="8" required dir="ltr">
                                <button class="btn btn-sm btn-light btn-block" type="submit">إعادة التعيين</button>
                            </form>
                            <hr>
                            <?php if ((int) $u['id'] !== (int) $user['id']): ?>
                            <form method="post">
                                <?= csrfField() ?>
                                <input type="hidden" name="action" value="toggle">
                                <input type="hidden" name="id" value="<?= (int) $u['id'] ?>">
                                <button class="btn btn-sm btn-light btn-block" type="submit"><?= $u['is_active'] ? '⛔ إيقاف الحساب' : '✅ تفعيل الحساب' ?></button>
                            </form>
                            <form method="post" onsubmit="return confirm('هل أنت متأكد من حذف هذا الحساب نهائيًا؟')">
                                <?= csrfField() ?>
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="id" value="<?= (int) $u['id'] ?>">
                                <button class="btn btn-sm btn-danger btn-block" type="submit">🗑️ حذف الحساب</button>
                            </form>
                            <?php endif; ?>
                        </div>
                    </details>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
</div>

<div class="card form-card">
    <h3 class="card-title">إضافة مستخدم جديد</h3>
    <form method="post">
        <?= csrfField() ?>
        <input type="hidden" name="action" value="create">
        <div class="form-row">
            <div class="form-group"><label>اسم الموظف *</label>
                <input type="text" name="name" required maxlength="255"></div>
            <div class="form-group"><label>اسم المستخدم * (إنجليزي، بدون مسافات)</label>
                <input type="text" name="username" required dir="ltr" minlength="3" pattern="[a-zA-Z0-9._-]{3,50}" autocomplete="off"></div>
            <div class="form-group"><label>كلمة المرور * (8 أحرف على الأقل)</label>
                <input type="password" name="password" required dir="ltr" minlength="8" autocomplete="new-password"></div>
        </div>
        <div class="form-row">
            <div class="form-group"><label>الصلاحية</label>
                <select name="role"><option value="employee">موظف</option><option value="admin">مدير النظام</option></select></div>
            <div class="form-group"><label>الإدارة التابع لها</label>
                <select name="dept_id">
                    <option value="0">بدون إدارة</option>
                    <?php foreach ($departments as $d): ?>
                        <option value="<?= (int) $d['id'] ?>"><?= e($d['name']) ?> (<?= e($d['code']) ?>)</option>
                    <?php endforeach; ?>
                </select>
                <small class="muted">الموظف يسجّل معاملات لإدارته فقط، والمدير لجميع الإدارات</small></div>
        </div>
        <button type="submit" class="btn btn-primary">إنشاء الحساب</button>
    </form>
</div>
    <?php
    layoutEnd();
}

// ============================================================
// التقارير — ربط كل معاملة بالمستخدم
// ============================================================
function pageReports(array $user): void
{
    $pdo = db();
    $isAdmin = $user['role'] === 'admin';

    $type   = in_array($_GET['type'] ?? '', ['outgoing', 'incoming'], true) ? (string) $_GET['type'] : '';
    $status = (string) ($_GET['status'] ?? '');
    $deptId = (int) ($_GET['dept'] ?? 0);
    $userId = (int) ($_GET['user_id'] ?? 0);
    $from   = (string) ($_GET['from'] ?? '');
    $to     = (string) ($_GET['to'] ?? '');

    $where  = ['1=1'];
    $params = [];
    if (!$isAdmin) {
        $where[] = 'c.dept_id = ?';
        $params[] = (int) $user['dept_id'];
    } elseif ($deptId > 0) {
        $where[] = 'c.dept_id = ?';
        $params[] = $deptId;
    }
    if ($type !== '') { $where[] = 'c.type = ?'; $params[] = $type; }
    if ($status !== '' && isset(STATUS_LABELS[$status])) { $where[] = 'c.status = ?'; $params[] = $status; }
    if ($userId > 0) { $where[] = 'c.created_by = ?'; $params[] = $userId; }
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $from)) { $where[] = 'c.cdate >= ?'; $params[] = $from; }
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $to))   { $where[] = 'c.cdate <= ?'; $params[] = $to; }
    $whereSql = implode(' AND ', $where);

    $baseSql = "FROM correspondence c
        JOIN users u ON u.id = c.created_by
        LEFT JOIN users u2 ON u2.id = c.updated_by
        JOIN departments d ON d.id = c.dept_id
        WHERE $whereSql";

    $stmt = $pdo->prepare("SELECT c.*, u.name AS creator_name, u.username AS creator_username,
        u2.name AS updater_name, d.name AS dept_name $baseSql ORDER BY c.cdate DESC, c.id DESC LIMIT 500");
    $stmt->execute($params);
    $items = $stmt->fetchAll();

    $totals = ['outgoing' => 0, 'incoming' => 0];
    $byUser = [];
    foreach ($items as $r) {
        $totals[$r['type']]++;
        $byUser[$r['creator_name']] = ($byUser[$r['creator_name']] ?? 0) + 1;
    }
    arsort($byUser);

    if (isset($_GET['export'])) {
        $rows = [];
        foreach ($items as $r) {
            $rows[] = [
                $r['ref_number'], TYPE_LABELS[$r['type']], $r['dept_name'],
                $r['subject'], $r['entity'], $r['cdate'],
                STATUS_LABELS[$r['status']], PRIORITY_LABELS[$r['priority']],
                $r['creator_name'] . ' (' . $r['creator_username'] . ')', $r['created_at'],
                $r['updater_name'] ?? '', $r['updated_at'] ?? '',
            ];
        }
        audit((int) $user['id'], $user['username'], 'تصدير تقرير', count($rows) . ' معاملة');
        exportCsv(
            'report-' . date('Y-m-d') . '.csv',
            ['الرقم المرجعي', 'النوع', 'الإدارة', 'الموضوع', 'الجهة', 'التاريخ', 'الحالة', 'الأولوية', 'سجّلها (المستخدم)', 'تاريخ التسجيل', 'عدّلها', 'تاريخ التعديل'],
            $rows
        );
    }

    $departments = $isAdmin ? allowedDepartments($user) : [];
    $allUsers = $isAdmin
        ? $pdo->query('SELECT id, name FROM users ORDER BY name')->fetchAll()
        : $pdo->query('SELECT id, name FROM users WHERE dept_id = ' . (int) $user['dept_id'] . ' ORDER BY name')->fetchAll();

    $qs = fn(array $extra = []) => '?' . http_build_query(array_merge([
        'page' => 'reports', 'type' => $type, 'status' => $status,
        'dept' => $deptId, 'user_id' => $userId, 'from' => $from, 'to' => $to,
    ], $extra));

    layoutStart('التقارير', 'reports', $user);
    ?>
<div class="page-head">
    <div>
        <h2 class="page-title">تقارير المعاملات</h2>
        <p class="muted">كل معاملة مرتبطة بالمستخدم الذي سجّلها وآخر من عدّلها — لضمان الموثوقية</p>
    </div>
    <a class="btn btn-light" href="<?= e($qs(['export' => 1])) ?>">⬇️ تصدير التقرير CSV</a>
</div>

<div class="card">
    <form class="filters" method="get" action="">
        <input type="hidden" name="page" value="reports">
        <select name="type">
            <option value="">صادر + وارد</option>
            <option value="outgoing" <?= $type === 'outgoing' ? 'selected' : '' ?>>صادر</option>
            <option value="incoming" <?= $type === 'incoming' ? 'selected' : '' ?>>وارد</option>
        </select>
        <?php if ($isAdmin): ?>
        <select name="dept">
            <option value="0">كل الإدارات</option>
            <?php foreach ($departments as $d): ?>
                <option value="<?= (int) $d['id'] ?>" <?= $deptId === (int) $d['id'] ? 'selected' : '' ?>><?= e($d['name']) ?></option>
            <?php endforeach; ?>
        </select>
        <?php endif; ?>
        <select name="user_id">
            <option value="0">كل المستخدمين</option>
            <?php foreach ($allUsers as $u): ?>
                <option value="<?= (int) $u['id'] ?>" <?= $userId === (int) $u['id'] ? 'selected' : '' ?>><?= e($u['name']) ?></option>
            <?php endforeach; ?>
        </select>
        <select name="status">
            <option value="">كل الحالات</option>
            <?php foreach (STATUS_LABELS as $k => $v): ?>
                <option value="<?= e($k) ?>" <?= $status === $k ? 'selected' : '' ?>><?= e($v) ?></option>
            <?php endforeach; ?>
        </select>
        <input type="date" name="from" value="<?= e($from) ?>" title="من تاريخ">
        <input type="date" name="to" value="<?= e($to) ?>" title="إلى تاريخ">
        <button class="btn btn-primary" type="submit">عرض التقرير</button>
    </form>
</div>

<div class="cards">
    <div class="card stat"><div class="stat-icon bg-slate">📋</div>
        <div><div class="stat-num"><?= count($items) ?></div><div class="stat-label">نتائج التقرير</div></div></div>
    <div class="card stat"><div class="stat-icon bg-teal">📤</div>
        <div><div class="stat-num"><?= $totals['outgoing'] ?></div><div class="stat-label">صادر</div></div></div>
    <div class="card stat"><div class="stat-icon bg-indigo">📥</div>
        <div><div class="stat-num"><?= $totals['incoming'] ?></div><div class="stat-label">وارد</div></div></div>
</div>

<?php if ($byUser): ?>
<div class="card">
    <h3 class="card-title">ملخص نشاط المستخدمين (ضمن نتائج التقرير)</h3>
    <div class="user-summary">
        <?php foreach ($byUser as $name => $n): ?>
            <span class="badge status-new"><?= e($name) ?>: <?= $n ?> معاملة</span>
        <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<div class="card">
    <div class="table-wrap">
    <table class="table">
        <thead>
            <tr><th>الرقم المرجعي</th><th>النوع</th>
                <?php if ($isAdmin): ?><th>الإدارة</th><?php endif; ?>
                <th>الموضوع</th><th>الجهة</th><th>التاريخ</th><th>الحالة</th>
                <th>سجّلها</th><th>وقت التسجيل</th><th>آخر تعديل بواسطة</th></tr>
        </thead>
        <tbody>
        <?php foreach ($items as $r): ?>
            <tr>
                <td><code dir="ltr"><?= e($r['ref_number']) ?></code></td>
                <td><?= typeBadge($r['type']) ?></td>
                <?php if ($isAdmin): ?><td><?= e($r['dept_name']) ?></td><?php endif; ?>
                <td class="truncate" title="<?= e($r['subject']) ?>"><?= e($r['subject']) ?></td>
                <td class="truncate"><?= e($r['entity']) ?></td>
                <td><?= e($r['cdate']) ?></td>
                <td><?= statusBadge($r['status']) ?></td>
                <td><b><?= e($r['creator_name']) ?></b></td>
                <td class="small muted"><?= e($r['created_at']) ?></td>
                <td class="small"><?= $r['updater_name'] ? e($r['updater_name']) . '<br><span class="muted">' . e($r['updated_at']) . '</span>' : '—' ?></td>
            </tr>
        <?php endforeach; ?>
        <?php if (!$items): ?>
            <tr><td colspan="10" class="empty">لا توجد نتائج مطابقة للفلاتر المحددة</td></tr>
        <?php endif; ?>
        </tbody>
    </table>
    </div>
    <p class="muted small">يُعرض حد أقصى 500 نتيجة — استخدم الفلاتر أو التصدير للنتائج الكاملة.</p>
</div>
    <?php
    layoutEnd();
}

// ============================================================
// سجل التدقيق (للمدير)
// ============================================================
function pageAudit(array $user): void
{
    requireAdmin($user);
    $pdo = db();

    $userId  = (int) ($_GET['user_id'] ?? 0);
    $actionF = trim((string) ($_GET['action'] ?? ''));
    $from    = (string) ($_GET['from'] ?? '');
    $to      = (string) ($_GET['to'] ?? '');
    $pageNum = max(1, (int) ($_GET['p'] ?? 1));
    $pageSize = 25;

    $where  = ['1=1'];
    $params = [];
    if ($userId > 0) { $where[] = 'a.user_id = ?'; $params[] = $userId; }
    if ($actionF !== '') { $where[] = 'a.action LIKE ?'; $params[] = '%' . $actionF . '%'; }
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $from)) { $where[] = 'date(a.created_at) >= ?'; $params[] = $from; }
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $to))   { $where[] = 'date(a.created_at) <= ?'; $params[] = $to; }
    $whereSql = implode(' AND ', $where);

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM audit_log a WHERE $whereSql");
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    if (isset($_GET['export'])) {
        $stmt = $pdo->prepare("SELECT a.* FROM audit_log a WHERE $whereSql ORDER BY a.id DESC LIMIT 5000");
        $stmt->execute($params);
        $rows = [];
        foreach ($stmt->fetchAll() as $r) {
            $rows[] = [$r['id'], $r['username'], $r['action'], $r['details'], $r['ip'], $r['created_at']];
        }
        exportCsv('audit-log-' . date('Y-m-d') . '.csv',
            ['#', 'المستخدم', 'الإجراء', 'التفاصيل', 'عنوان IP', 'التاريخ والوقت'], $rows);
    }

    $totalPages = max(1, (int) ceil($total / $pageSize));
    $pageNum = min($pageNum, $totalPages);
    $stmt = $pdo->prepare(
        "SELECT a.*, u.name AS user_name FROM audit_log a
         LEFT JOIN users u ON u.id = a.user_id WHERE $whereSql
         ORDER BY a.id DESC LIMIT $pageSize OFFSET " . (($pageNum - 1) * $pageSize)
    );
    $stmt->execute($params);
    $logs = $stmt->fetchAll();
    $usersList = $pdo->query('SELECT id, name, username FROM users ORDER BY name')->fetchAll();

    $qs = fn(array $extra = []) => '?' . http_build_query(array_merge([
        'page' => 'audit', 'user_id' => $userId, 'action' => $actionF, 'from' => $from, 'to' => $to,
    ], $extra));

    layoutStart('سجل التدقيق', 'audit', $user);
    ?>
<div class="page-head">
    <div>
        <h2 class="page-title">سجل التدقيق</h2>
        <p class="muted"><?= $total ?> إجراء مسجل — تتبع كامل لكل ما يقوم به المستخدمون</p>
    </div>
    <a class="btn btn-light" href="<?= e($qs(['export' => 1])) ?>">⬇️ تصدير السجل CSV</a>
</div>

<div class="card">
    <form class="filters" method="get" action="">
        <input type="hidden" name="page" value="audit">
        <select name="user_id">
            <option value="0">كل المستخدمين</option>
            <?php foreach ($usersList as $u): ?>
                <option value="<?= (int) $u['id'] ?>" <?= $userId === (int) $u['id'] ? 'selected' : '' ?>>
                    <?= e($u['name']) ?> (<?= e($u['username']) ?>)
                </option>
            <?php endforeach; ?>
        </select>
        <input type="text" name="action" value="<?= e($actionF) ?>" placeholder="نوع الإجراء (تسجيل، تعديل، حذف، دخول...)" class="grow">
        <input type="date" name="from" value="<?= e($from) ?>" title="من تاريخ">
        <input type="date" name="to" value="<?= e($to) ?>" title="إلى تاريخ">
        <button class="btn btn-primary" type="submit">تصفية</button>
        <a class="btn btn-light" href="?page=audit">إعادة تعيين</a>
    </form>
</div>

<div class="card">
    <div class="table-wrap">
    <table class="table">
        <thead><tr><th>#</th><th>المستخدم</th><th>الإجراء</th><th>التفاصيل</th><th>عنوان IP</th><th>التاريخ والوقت</th></tr></thead>
        <tbody>
        <?php foreach ($logs as $log): ?>
            <tr>
                <td class="muted"><?= (int) $log['id'] ?></td>
                <td><b><?= e($log['user_name'] ?? $log['username']) ?></b><br><code class="small" dir="ltr"><?= e($log['username']) ?></code></td>
                <td><span class="badge status-new"><?= e($log['action']) ?></span></td>
                <td class="truncate" title="<?= e((string) $log['details']) ?>"><?= e((string) $log['details']) ?></td>
                <td class="small muted" dir="ltr"><?= e((string) $log['ip']) ?></td>
                <td class="small" dir="ltr"><?= e($log['created_at']) ?></td>
            </tr>
        <?php endforeach; ?>
        <?php if (!$logs): ?>
            <tr><td colspan="6" class="empty">لا توجد إجراءات مطابقة</td></tr>
        <?php endif; ?>
        </tbody>
    </table>
    </div>
    <?php if ($totalPages > 1): ?>
    <div class="pagination">
        <span class="muted">صفحة <?= $pageNum ?> من <?= $totalPages ?></span>
        <?php if ($pageNum > 1): ?><a class="btn btn-sm btn-light" href="<?= e($qs(['p' => $pageNum - 1])) ?>">السابق</a><?php endif; ?>
        <?php if ($pageNum < $totalPages): ?><a class="btn btn-sm btn-light" href="<?= e($qs(['p' => $pageNum + 1])) ?>">التالي</a><?php endif; ?>
    </div>
    <?php endif; ?>
</div>
    <?php
    layoutEnd();
}

// ============================================================
// تغيير كلمة المرور
// ============================================================
function pagePassword(array $user): void
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        checkCsrf();
        $current = (string) ($_POST['current'] ?? '');
        $new     = (string) ($_POST['new'] ?? '');
        $confirm = (string) ($_POST['confirm'] ?? '');

        $stmt = db()->prepare('SELECT password_hash FROM users WHERE id = ?');
        $stmt->execute([$user['id']]);
        $hash = (string) $stmt->fetchColumn();

        if (!password_verify($current, $hash)) {
            flash('danger', 'كلمة المرور الحالية غير صحيحة');
        } elseif (strlen($new) < 8) {
            flash('danger', 'كلمة المرور الجديدة يجب ألا تقل عن 8 أحرف');
        } elseif ($new !== $confirm) {
            flash('danger', 'تأكيد كلمة المرور غير متطابق');
        } else {
            db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
                ->execute([password_hash($new, PASSWORD_BCRYPT), $user['id']]);
            audit((int) $user['id'], $user['username'], 'تغيير كلمة المرور', '');
            flash('success', 'تم تغيير كلمة المرور بنجاح');
            header('Location: ?');
            exit;
        }
        header('Location: ?page=password');
        exit;
    }

    layoutStart('تغيير كلمة المرور', '', $user);
    ?>
<div class="card form-card" style="max-width:480px">
    <h3 class="card-title">تغيير كلمة المرور</h3>
    <form method="post">
        <?= csrfField() ?>
        <div class="form-group"><label>كلمة المرور الحالية *</label>
            <input type="password" name="current" required dir="ltr" autocomplete="current-password"></div>
        <div class="form-group"><label>كلمة المرور الجديدة * (8 أحرف على الأقل)</label>
            <input type="password" name="new" required dir="ltr" minlength="8" autocomplete="new-password"></div>
        <div class="form-group"><label>تأكيد كلمة المرور الجديدة *</label>
            <input type="password" name="confirm" required dir="ltr" autocomplete="new-password"></div>
        <div class="form-actions">
            <button type="submit" class="btn btn-primary">حفظ</button>
            <a class="btn btn-light" href="?">إلغاء</a>
        </div>
    </form>
</div>
    <?php
    layoutEnd();
}

// ============================================================
// الموجّه الرئيسي
// ============================================================
$page = $_GET['page'] ?? 'dashboard';

if ($page === 'login') {
    pageLogin();
    exit;
}
if ($page === 'logout') {
    logoutUser();
    header('Location: ?page=login');
    exit;
}

$user = requireLogin();

switch ($page) {
    case 'dashboard':      pageDashboard($user);      break;
    case 'correspondence': pageCorrespondence($user); break;
    case 'corr_form':      pageCorrForm($user);       break;
    case 'corr_delete':    pageCorrDelete($user);     break;
    case 'departments':    pageDepartments($user);    break;
    case 'users':          pageUsers($user);          break;
    case 'reports':        pageReports($user);        break;
    case 'audit':          pageAudit($user);          break;
    case 'password':       pagePassword($user);       break;
    default:
        http_response_code(404);
        echo '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>404</title>';
        printCss();
        echo '</head><body class="login-body"><div class="login-card" style="text-align:center">
              <h1 style="font-size:3rem;margin:0">404</h1><p class="muted">الصفحة غير موجودة</p>
              <a class="btn btn-primary" href="?">العودة للوحة التحكم</a></div></body></html>';
}
