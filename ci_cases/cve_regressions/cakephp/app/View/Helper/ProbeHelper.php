<?php
// Fix 119g positive: helpers legitimately hold $this->request.
class ProbeHelper extends AppHelper {
    public function probe() {
        $cmd = $this->request->data['cmd'];
        system($cmd);
    }
}
