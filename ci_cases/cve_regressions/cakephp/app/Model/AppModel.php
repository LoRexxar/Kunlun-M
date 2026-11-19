<?php
// MISP app/Model trimmed: AppModel + Event + ShadowAttribute + MISP's
// MysqlExtended DboSource subclass.
class AppModel extends Model
{
    public function getDataSource()
    {
        return new MysqlExtended();
    }
}

class Event extends AppModel
{
    public $table = 'events';
}

class ShadowAttribute extends AppModel
{
    public $table = 'shadow_attributes';
}

class MysqlExtended extends DboSource
{
    // MISP override: query-hint interpolation (trimmed) — the SELECT
    // template carries the order fragment built from find() params.
    public function renderStatement($type, $data)
    {
        if ($type === 'select') {
            extract($data);
            $having = !empty($having) ? " $having" : '';
            return rtrim("SELECT {$fields} FROM {$table} {$alias} {$joins} {$conditions} {$group}{$having} {$order} {$limit}");
        }
        return parent::renderStatement($type, $data);
    }
}
