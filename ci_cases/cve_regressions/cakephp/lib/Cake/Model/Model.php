<?php
// CakePHP 2.x Model base (trimmed from lib/Cake/Model/Model.php).
class Model extends Object
{
    public $table = '';
    public $useDbConfig = 'default';

    public function find($type = 'first', $query = array())
    {
        // Model::find → DboSource::read — the ORM entry every controller
        // query goes through (real signature kept).
        $db = $this->getDataSource();
        return $db->read($this, $query);
    }

    public function getDataSource()
    {
        return new DboSource();
    }
}
