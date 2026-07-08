<?php
/**
 * Real-world style SQL Injection test cases.
 *
 * 模拟一个简单的博客 / 评论搜索后端控制器，覆盖 CVI-1005 (mysql_query) 与
 * CVI-1006 (mysqli_query)。每个测试包含 VULN 与 SAFE 两种模式。
 *
 * 预期检出：CVI-1005, CVI-1006（仅 VULN 分支）
 */

require_once __DIR__ . '/db.php';

class CommentRepository
{
    /** @var mysqli */
    private $conn;

    public function __construct($conn)
    {
        $this->conn = $conn;
    }

    /**
     * VULN-1 (CVI-1005): 老式 mysql_query 接口，$keyword 直接拼接到 SQL 字符串里。
     * 用户输入 $_GET['q'] -> $keyword -> mysql_query，整条链路全部可控。
     */
    public function legacySearch($keyword)
    {
        $keyword = $_GET['q'];
        $query = "SELECT id, content FROM comments WHERE content LIKE '%" . $keyword . "%' ORDER BY id DESC";

        // 老接口 mysql_query 直接执行拼接好的 SQL
        $result = mysql_query($query, $this->conn);
        return $result;
    }

    /**
     * VULN-2 (CVI-1006): mysqli_query 接口同样使用字符串拼接，依然存在 SQL 注入。
     * 这条污点链路穿过 searchByAuthor() -> buildQuery() -> mysqli_query。
     */
    public function searchByAuthor($authorName)
    {
        $authorName = $_GET['author'];
        $sql = $this->buildAuthorQuery($authorName);
        return mysqli_query($this->conn, $sql);
    }

    /**
     * 辅助方法：构造 SQL，看似封装但实际还是字符串拼接。
     */
    private function buildAuthorQuery($name)
    {
        return "SELECT * FROM comments WHERE author = '" . $name . "' LIMIT 20";
    }

    /**
     * SAFE-1: 参数化查询 (mysqli_prepare + bind_param)，无注入风险。
     */
    public function safeSearch()
    {
        $keyword = $_GET['q'];
        $stmt = $this->conn->prepare("SELECT id, content FROM comments WHERE content LIKE ? ORDER BY id DESC");
        $param = '%' . $keyword . '%';
        $stmt->bind_param('s', $param);
        $stmt->execute();
        return $stmt->get_result();
    }

    /**
     * SAFE-2: 显式白名单过滤，仅允许字母数字与下划线，从根本上切断污点。
     */
    public function safeSearchWhitelisted()
    {
        $keyword = $_GET['q'];
        if (!preg_match('/^[A-Za-z0-9_]+$/', $keyword)) {
            return array();
        }
        $sql = "SELECT id, content FROM comments WHERE content LIKE '%" . $keyword . "%'";
        return mysqli_query($this->conn, $sql);
    }
}

// 模拟 HTTP 入口，构造对象并调用，确保污点链路被引擎跟踪。
$repo = new CommentRepository($db_conn);
if (isset($_GET['q'])) {
    $rows = $repo->legacySearch($_GET['q']);
}
if (isset($_GET['author'])) {
    $rows = $repo->searchByAuthor($_GET['author']);
}
