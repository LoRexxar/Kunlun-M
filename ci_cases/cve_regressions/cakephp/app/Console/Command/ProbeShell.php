<?php
// Fix 119g negative: Shell::$params is CLI argv, NOT a web source.
class ProbeShell extends AppShell {
    public function main() {
        $cmd = $this->params['cmd'];
        system($cmd);
    }
}
