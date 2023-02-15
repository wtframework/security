<?php

declare(strict_types=1);

namespace WTFramework\Security;

use WTFramework\Config\Config;

class Crypto
{

  public const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
  public const ENCRYPTION_OPTIONS = 0;
  public const HASH_ALGORITHM = 'sha3-512';
  public const HASH_ITERATIONS = 10000;

  private function __construct() {}

  public static function encrypt(
    string $plaintext,
    string $algorithm = null,
    int $options = null
  ): string
  {

    $ciphertext = openssl_encrypt(
      $plaintext,
      $algorithm ??= (string) Config::get(
        key: 'security.encryption_algorithm',
        default: self::ENCRYPTION_ALGORITHM
      ),
      (string) Config::get(key: 'security.encryption_key'),
      $options ?? (int) Config::get(
        key: 'security.encryption_options',
        default: self::ENCRYPTION_OPTIONS
      ),
      $iv = bin2hex(random_bytes(openssl_cipher_iv_length($algorithm) / 2)),
      $tag
    );

    return "$iv$" . bin2hex($tag ?: '') . "$$ciphertext";

  }

  public static function decrypt(
    ?string $ciphertext,
    string $algorithm = null,
    int $options = null
  ): string
  {

    if (!$ciphertext)
    {
      return '';
    }

    [$iv, $tag, $data] = explode('$', $ciphertext, 3);

    return openssl_decrypt(
      $data ?: '',
      $algorithm ?? (string) Config::get(
        key: 'security.encryption_algorithm',
        default: self::ENCRYPTION_ALGORITHM
      ),
      (string) Config::get(key: 'security.encryption_key'),
      $options ?? (int) Config::get(
        key: 'security.encryption_options',
        default: self::ENCRYPTION_OPTIONS
      ),
      $iv,
      $tag ? hex2bin($tag) : null
    ) ?: '';

  }

  public static function hash(
    string $plaintext,
    string $algorithm = null,
    int $iterations = null
  ): string
  {

    return hash_pbkdf2(
      $algorithm ?? (string) Config::get(
        key: 'security.hash_algorithm',
        default: self::HASH_ALGORITHM
      ),
      $plaintext,
      (string) Config::get(key: 'security.hash_salt'),
      $iterations ?? (int) Config::get(
        key: 'security.hash_iterations',
        default: self::HASH_ITERATIONS
      )
    );

  }

  public static function uuid(): string
  {

    $uuid = random_bytes(16);

    $uuid[6] = chr(ord($uuid[6]) & 0x0f | 0x40);
    $uuid[8] = chr(ord($uuid[8]) & 0x3f | 0x80);

    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($uuid), 4));

  }

}