<?php

// Get sender domain , if is fleco_unova who fetch request ok else no
namespace SecureToken;

class SecureToken{
  private String $firstKey;
  private String $secondKey;
  private String $secret = 'www.vianney.fr';
  private String $encryptMethod ="aes-256-cbc";
  private int $sha2len = 32;

  /**
   * @description: Constructor
   * @return void
   */
  public function __construct() {
    try {
      $configs = file_get_contents(__DIR__."/../config/token_generator.json");
      $this->configs(json_decode($configs));
    } catch (Exception $e) { echo $e->getMessages(); }
  }
  
  /**
   * @description: encrypting token
   * @param String $data
   * @return String data encrypted
   */
  public function tokenencrypt(String $data): String {
    // Génère une chaîne d'octets pseudo-aléatoires.
    $iv = openssl_random_pseudo_bytes($this->ivlen());
    // Chiffre les données passées avec la méthode et la 1ére clé de chiffrement
    $firstEncrypted = openssl_encrypt($data, $this->encryptMethod, $this->firstKey, OPENSSL_RAW_DATA, $iv);
    //Génère une valeur de clé de hachage en utilisant la méthode HMAC
    //clé de hashage basé sur la 2eme cles, de l encryptage de $data basé sur la 1er clés
    $secondEncrypted = hash_hmac('sha256', $firstEncrypted, $this->secondKey, true);

    return base64_encode($iv.$secondEncrypted.$firstEncrypted);
  }

  /**
  * @description: decrypting token
  * @param String $data
  * @return String data decrypted
  */
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

  /**
   * @description: gets the length of the encryption initialization vector (iv)
   * @return int
   */
  private function ivlen(): int { return openssl_cipher_iv_length($this->encryptMethod); }
}
