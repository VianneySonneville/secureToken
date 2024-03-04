<?php
require __DIR__. '/../SecureToken.php';
use SecureToken\SecureToken;

$st= new SecureToken();
$w = "cecciestuntest";

if ($w === $st->tokendecrypt($st->tokenencrypt($w))){
  echo "success !\n";
} else {
  echo "Error !\n";
}