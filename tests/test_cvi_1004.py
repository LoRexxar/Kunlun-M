import re

from rules.php.CVI_1004 import CVI_1004


def test_cvi_1004_extracts_all_sql_variables_in_assignment():
    rule = CVI_1004()
    code = (
        '$query  = "SELECT id, name, inserted, size FROM products WHERE size = '
        '\'${size}\' ORDER BY $order LIMIT $limit, $offset;";'
    ).replace('${size}', '$size')

    matched = re.findall(rule.match, code)
    assert matched
    assert rule.main(matched) == ['$size', '$order', '$limit', '$offset']


def test_cvi_1004_does_not_leak_variables_from_non_sql_branches():
    rule = CVI_1004()
    code = (
        "if ($getInfo['expire']>time()) {$plan = $odb -> query(\"SELECT `plans`.`name` "
        "FROM `users`, `plans` WHERE `plans`.`ID` = `users`.`membership` AND "
        "`users`.`ID` = '$id'\") -> fetchColumn(0);} else {$plan='No membership';}"
    )

    matched = re.findall(rule.match, code)
    assert matched
    assert rule.main(matched) == ['$id']


def test_cvi_1004_keeps_variables_from_sql_concatenation():
    rule = CVI_1004()
    code = (
        '$sql = "SELECT id, name FROM products WHERE 1=1 " . $where . '
        '" ORDER BY " . $order . ";";'
    )

    matched = re.findall(rule.match, code)
    assert matched
    assert rule.main(matched) == ['$where', '$order']


def test_cvi_1004_handles_sql_without_semicolon():
    rule = CVI_1004()
    code = (
        "if ($getInfo['expire']>time()) {$plan = $odb -> query(\"SELECT `plans`.`name` "
        "FROM `users`, `plans` WHERE `users`.`ID` = '$id'\") -> fetchColumn(0)} "
        "else {$plan='No membership';}"
    )

    matched = re.findall(rule.match, code)
    assert matched
    assert rule.main(matched) == ['$id']
