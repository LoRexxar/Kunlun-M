<?php
// Faithful trim of MISP 2.5.36 app/Controller/EventsController.php index /
// __indexRestResponse (CVE-2026-44381 sink A). Pre-fix shape: 'order' kept in
// $paginationRules and copied verbatim into Model::find() rules.
class AppController extends Controller
{
    public function _isRest()
    {
        return true;
    }
}

class EventsController extends AppController
{
    public $uses = array('Event');

    public function index()
    {
        // EventsController.php:712 — framework source property
        $passedArgs = $this->passedArgs;
        if ($this->_isRest()) {
            return $this->__indexRestResponse($passedArgs);
        }
    }

    // EventsController.php:830 (pre-fix 2.5.36)
    private function __indexRestResponse(array $passedArgs)
    {
        $rules = array();
        $fieldNames = array('Event.id' => true, 'Event.date' => true, 'Event.info' => true);

        if (isset($passedArgs['sort']) && isset($fieldNames[$passedArgs['sort']])) {
            if (isset($passedArgs['direction']) && in_array(strtoupper($passedArgs['direction']), array('ASC', 'DESC'))) {
                $rules['order'] = array('Event.' . $passedArgs['sort'] => $passedArgs['direction']);
            } else {
                $rules['order'] = array('Event.' . $passedArgs['sort'] => 'ASC');
            }
        }

        $paginationRules = array('page', 'limit', 'sort', 'direction', 'order');
        foreach ($paginationRules as $paginationRule) {
            if (isset($passedArgs[$paginationRule])) {
                $rules[$paginationRule] = $passedArgs[$paginationRule];
            }
        }

        // EventsController.php:883 — tainted $rules['order'] into ORM find
        $temp = $this->Event->find('all', $rules);
        return $temp;
    }
}
