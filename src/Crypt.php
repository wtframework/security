<?php

declare(strict_types=1);

namespace WTFramework\Security;

use WTFramework\Config\Config;

abstract class Crypt
{

  public const ENCRYPTION_ALGORITHM = 'aes-128-gcm';
  public const ENCRYPTION_OPTIONS = 0;
  public const HASH_ALGORITHM = 'sha3-512';
  public const HASH_ITERATIONS = 10000;

  private function __construct() {}

  public static function encrypt(string $plaintext): string
  {

    $ciphertext = openssl_encrypt(
      $plaintext,
      $algorithm = static::encryptionAlgorithm(),
      static::encryptionKey(),
      static::encryptionOptions(),
      $iv = bin2hex(random_bytes(openssl_cipher_iv_length($algorithm) / 2)),
      $tag
    );

    return "$iv$" . bin2hex($tag ?: '') . "$$ciphertext";

  }

  public static function decrypt(?string $ciphertext): string
  {

    if (!$ciphertext)
    {
      return '';
    }

    [$iv, $tag, $data] = explode('$', $ciphertext, 3);

    return openssl_decrypt(
      (string) $data,
      static::encryptionAlgorithm(),
      static::encryptionKey(),
      static::encryptionOptions(),
      $iv,
      $tag ? hex2bin($tag) : null
    ) ?: '';

  }

  public static function hash(string $plaintext): string
  {

    return hash_pbkdf2(
      static::hashAlgorithm(),
      $plaintext,
      static::hashSalt(),
      static::hashIterations()
    );

  }

  public static function uuid(): string
  {

    $uuid = random_bytes(16);

    $uuid[6] = chr(ord($uuid[6]) & 0x0f | 0x40);
    $uuid[8] = chr(ord($uuid[8]) & 0x3f | 0x80);

    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($uuid), 4));

  }

  public static function encryptionKey(): string
  {
    return (string) Config::get(key: 'security.encryption_key');
  }

  public static function encryptionAlgorithm(): string
  {

    return (string) Config::get(
      key: 'security.encryption_algorithm',
      default: static::ENCRYPTION_ALGORITHM
    );

  }

  public static function encryptionOptions(): int
  {

    return (int) Config::get(
      key: 'security.encryption_options',
      default: static::ENCRYPTION_OPTIONS
    );

  }

  public static function hashSalt(): string
  {
    return (string) Config::get(key: 'security.hash_salt');
  }

  public static function hashAlgorithm(): string
  {

    return (string) Config::get(
      key: 'security.hash_algorithm',
      default: static::HASH_ALGORITHM
    );

  }

  public static function hashIterations(): int
  {

    return (int) Config::get(
      key: 'security.hash_iterations',
      default: static::HASH_ITERATIONS
    );

  }

}