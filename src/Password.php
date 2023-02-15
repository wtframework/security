<?php

declare(strict_types=1);

namespace WTFramework\Security;

use WTFramework\Config\Config;

class Password
{

  public const ALGORITHM = PASSWORD_DEFAULT;
  public const COST = 12;

  public function __construct(public readonly string $password) {}

  protected function pepper(): string
  {

    return !isset($this->password[71]) ? substr(
      (string) Config::get(key: 'security.password_pepper'),
      0,
      72 - strlen($this->password)
    ) : '';

  }

  public function hash(): string
  {

    return password_hash(
      $this->pepper() . $this->password,
      self::ALGORITHM,
      ['cost' => self::COST]
    );

  }

  public function verify(string $hash): bool
  {

    return password_verify(
      $this->pepper() . $this->password,
      $hash
    );

  }

  public static function needsRehash(string $hash): bool
  {

    return password_needs_rehash(
      $hash,
      self::ALGORITHM,
      ['cost' => self::COST]
    );

  }

}