<?php

declare(strict_types=1);

namespace WTFramework\Security;

use WTFramework\Config\Config;

abstract class Password
{

  public const ALGORITHM = PASSWORD_DEFAULT;
  public const OPTIONS = ['cost' => 12];

  private function __construct() {}

  public static function hash(string $password): string
  {

    return password_hash(
      $password . static::pepper(),
      static::algorithm(),
      static::options()
    );

  }

  public static function verify(
    string $password,
    string $hash
  ): bool
  {

    return password_verify(
      $password . static::pepper(),
      $hash
    );

  }

  public static function needsRehash(string $hash): bool
  {

    return password_needs_rehash(
      $hash,
      static::algorithm(),
      static::options()
    );

  }

  public static function pepper(): string
  {
    return (string) Config::get(key: 'security.password_pepper');
  }

  public static function algorithm(): string
  {

    return (string) Config::get(
      key: 'security.password_algorithm',
      default: static::ALGORITHM
    );

  }

  public static function options(): array
  {

    return (array) Config::get(
      key: 'security.password_options',
      default: static::OPTIONS
    );

  }

}