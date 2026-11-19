<?php
// Faithful trim of CakePHP 2.x Model + DboSource path
// (app/Lib/cakephp/lib/Cake/Model/Model.php find() → DboSource read() →
// renderStatement() → execute()) plus MISP's own MysqlExtended
// (app/Model/Datasource/Database/MysqlExtended.php) which overrides
// renderStatement with query-hint interpolation.
class DboSource
{
    public function read($model, $queryData = array())
    {
        // DboSource::read → buildStatement: the order fragment from the
        // controller's find() params flows into the SELECT template.
        $order = '';
        if (!empty($queryData['order'])) {
            $order = is_array($queryData['order'])
                ? implode(', ', Set::format($queryData['order']))
                : (string)$queryData['order'];
        }
        $sql = $this->renderStatement('select', array(
            'fields' => '*',
            'table' => $model->table,
            'conditions' => '',
            'order' => $order,
        ));
        return $this->execute($sql);
    }

    public function renderStatement($type, $data)
    {
        extract($data);
        return rtrim("SELECT {$fields} FROM {$table} {$conditions} ORDER BY {$order}");
    }

    public function execute($sql)
    {
        // terminal DB sink — DboSource::_execute → mysqli query
        return $this->_execute($sql);
    }

    public function _execute($sql)
    {
        $conn = MysqlExtended::$connection;
        return mysqli_query($conn, $sql);
    }

    public static $connection = null;
}

class Set
{
    // stub of CakePHP Set utility used above
    public static function format($arr)
    {
        return array_keys($arr);
    }
}
