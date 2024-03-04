<?php

// Get sender domain , if is fleco_unova who fetch request ok else no
namespace SecureToken;

class SecureToken{
  private $firstKey;
  private $secondKey;
  private $secret = 'www.vianney.fr';
  private $encryptMethod ="aes-256-cbc";
  private $sha2len = 32;

  public function __construct() {
    try {
      $configs = file_get_contents(__DIR__."/../config/token_generator.json");
      $this->configs(json_decode($configs));
    } catch (Exception $e) { echo $e->getMessages(); }
  }
  
  public function tokenencrypt($data) {
    // Génère une chaîne d'octets pseudo-aléatoires.
    $iv = openssl_random_pseudo_bytes($this->ivlen());
    // Chiffre les données passées avec la méthode et la 1ére clé de chiffrement
    $firstEncrypted = openssl_encrypt($data, $this->encryptMethod, $this->firstKey, OPENSSL_RAW_DATA, $iv);
    //Génère une valeur de clé de hachage en utilisant la méthode HMAC
    //clé de hashage basé sur la 2eme cles, de l encryptage de $data basé sur la 1er clés
    $secondEncrypted = hash_hmac('sha256', $firstEncrypted, $this->secondKey, true);

    return base64_encode($iv.$secondEncrypted.$firstEncrypted);
  }

  public function tokendecrypt($data): ?String {
    $mix = base64_decode($data);
    $iv = substr($mix, 0, $this->ivlen());
    $secondEncrypted = substr($mix, $this->ivlen(), $this->sha2len);
    $firstEncrypted = substr($mix, $this->ivlen() + $this->sha2len);
    $original_data = openssl_decrypt($firstEncrypted, $this->encryptMethod, $this->firstKey, OPENSSL_RAW_DATA, $iv);
    $secondEncryptedNew = hash_hmac('sha256', $firstEncrypted, $this->secondKey, true);
    
    // timing attack safe comparison
    return hash_equals($secondEncrypted, $secondEncryptedNew) ? $original_data : null;
  }

  /**
   * @description: Configs initialization
   * @param \stdClass $configs
   * @return void
   */
  private function configs(\stdClass $configs): void {
    $this->firstKey = $configs->token_generator->first_key;
    $this->secondKey = $configs->token_generator->second_key;
  }

  // Obtient la longueur du vecteur d'initialisation de chiffrement (iv).
  private function ivlen(): int { return openssl_cipher_iv_length($this->encryptMethod); }
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


// BDD
// PROBLEME: exemple une requête SQL qui permet de sélectionner l’identifiant d’un utilisateur à partir de son login et de son mot de passe.
// SELECT identifiant FROM utilisateur WHERE login = 'nom_utilisateur' AND password = 'XC5AF32';
// RISQUE: Dans cette requête, le login est entré par l’utilisateur. Or, si celui ci indique que son login est “admin’ —” 
// SELECT identifiant FROM utilisateur WHERE login = 'admin' --' AND password = 'faux_password';
// FAIL: Les 2 tirets signifient que le reste de la requête est en commentaire. Dès lors, il est possible de se connecter sur le compte de l’administrateur et d’avoir accès à toutes les données sensibles d’un site ou d’une application.

// RESOLUTION: Utiliser PDO
// Sinon:

// function sanitize_string($str) { // PHP 5 with mysqli
// 	if (function_exists('get_magic_quotes_gpc') && get_magic_quotes_gpc()) { // get_magic_quotes_gpc for php 5 depreced since php 7
// 		$sanitize = mysqli_real_escape_string(stripslashes($str));	 
// 	} else {
// 		$sanitize = mysqli_real_escape_string($str);	
// 	} 
// 	return $sanitize;
// }

// function sanitize_string($str) { // PHP 5 et < 5.5 with mysql
// 	if (function_exists('get_magic_quotes_gpc') && get_magic_quotes_gpc()) {
// 		$sanitize = mysql_real_escape_string(stripslashes($str));	 
// 	} else {
// 		$sanitize = mysql_real_escape_string($str);	
// 	} 
// 	return $sanitize;
// }

function sanitize_string($str) { // < 4.3
	$sanitize = addslashes($str);	
	return $sanitize;
}

// Le principe est de ne pas interpréter les simple quotes

// echo sanitize_string("SELECT identifiant FROM utilisateur WHERE login = 'admin' --' AND password = 'faux_password';");

// Avantage de la fonction
// Cette fonction est à utiliser sur chaque $_GET ou $_POST qui iront dans une requête SQL. 
// Elle transforme notamment le guillemet simple en son équivalent en entité HTML. 
// Il est pratique d’utiliser une telle fonction car si un jour le système de base de données est modifié, 
// il suffit juste de changer la fonction mysqli_real_escapte_string() 
// à l’intérieur au lieu de faire des modifications dans tout le reste du code.

// PROBLEME un champ de recherche. Nous avons en effet un champ pour rechercher une liste d’articles de blogs se trouvants dans la table article
// Recheche de 'php'
// $sql = "SELECT `id`,`title` FROM `article` WHERE `title` LIKE '%". $_POST['search'] ."%'";
// Donc, si on saisit la recherche « php », la requête SQL ne posera pas de problème.
// RISQUE: injection d'un point virgule.
// Maintenant, si on rentre la recherche suivante « a’; DELETE * FROM article; ». La requête donnera ce qui suit :
// FAIL: SELECT `id`,`title` FROM `article` WHERE `title` LIKE '%a'; DELETE * FROM article;%'