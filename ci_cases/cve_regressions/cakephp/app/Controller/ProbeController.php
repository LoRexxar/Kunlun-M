<?php
// Fix 119g positive: Controller passedArgs IS a web source (GT pattern).
class ProbeController extends AppController {
    public function index() {
        $rules = array();
        $rules['order'] = $this->passedArgs['sort'];
        $results = $this->Event->find('all', $rules);
        return $results;
    }
}
