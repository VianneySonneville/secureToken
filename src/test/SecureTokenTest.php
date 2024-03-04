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

// $access_token = md5(uniqid().rand(1000000, 9999999));
// // on stock ce token en bdd
// echo "Enreistrement du token $access_token \n";
// // on encrypte le token basé sur deux mot clés pour s assuré de ca provenance.
// $tokenencrypt = secureToken::tokenencrypt($access_token);
// // token envoyé au client:
// echo "$tokenencrypt \n";
// // on imagine donc que le client envoie le token:
// // on s'assure que le token est bien decrypté et qu elle correspond a notre token d'origine:
// $tokendecrypt = secureToken::tokendecrypt($tokenencrypt);
// echo "token_decrypt: $tokendecrypt \n";
// echo "token_origine: $access_token \n";