<?php

declare(strict_types=1);

namespace Test;

use WTFramework\Security\Password;

abstract class CustomPassword extends Password
{
  public const OPTIONS = ['cost' => 10];
}