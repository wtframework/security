<?php

declare(strict_types=1);

use Test\CustomPassword;
use WTFramework\Config\Config;
use WTFramework\Security\Password;

beforeAll(function ()
{

  Config::set([
    'security' => [
      'password_pepper' => bin2hex(random_bytes(36)),
    ],
  ]);

});

it('can verify password', function ()
{

  $password = 'foo';

  expect(Password::verify(
    $password,
    Password::hash($password)
  ))
  ->toBeTrue();

  expect(Password::verify(
    $password,
    Password::hash('bar')
  ))
  ->toBeFalse();

});

it('can need rehash', function ()
{

  expect(Password::needsRehash(CustomPassword::hash('foo')))
  ->toBeTrue();

  expect(Password::needsRehash(Password::hash('foo')))
  ->toBeFalse();

});