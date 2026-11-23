<?php
// Faithful trim of MISP 2.5.36 app/Controller/ShadowAttributesController.php
// index() (CVE-2026-44381 sink B). Pre-fix shape: named 'sort'/'direction'
// concatenated straight into the ORDER BY fragment.
class ShadowAttributesController extends AppController
{
    public $uses = array('ShadowAttribute');

    public function index($eventId = false)
    {
        $params = array(
            'conditions' => array(),
            'recursive' => -1
        );
        $simpleParams = array('limit', 'page');
        foreach ($simpleParams as $simpleParam) {
            if (!empty($this->request['named'][$simpleParam])) {
                $params[$simpleParam] = $this->request['named'][$simpleParam];
            }
        }
        // ShadowAttributesController.php:889 — concat of user sort field
        if (isset($this->request['named']['sort'])) {
            $params['order'] = 'ShadowAttribute.' . $this->request['named']['sort'];
            if (!empty($this->request['named']['direction'])) {
                $direction = trim(strtolower($this->request['named']['direction']));
                $params['order'] .= ' ' . ($direction === 'asc' ? 'ASC' : 'DESC');
            } else {
                $params['order'] .= ' ASC';
            }
        }

        // ShadowAttributesController.php:899 — ORM find with tainted order
        $results = $this->ShadowAttribute->find('all', $params);
        return $results;
    }
}
