<?php
function getUser($conn) {
    $id = $_GET['id'];
    mysql_query("SELECT * FROM users WHERE id=" . $id);
}
