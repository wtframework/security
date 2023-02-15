<?php

declare(strict_types=1);

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

  $password = new Password('foo');

  expect($password->verify($password->hash()))
  ->toBeTrue();

  expect($password->verify((new Password('bar'))->hash()))
  ->toBeFalse();

});

it('can need rehash', function ()
{

  expect(Password::needsRehash(password_hash(
    'foo',
    Password::ALGORITHM,
    ['cost' => Password::COST + 1]
  )))
  ->toBeTrue();

  expect(Password::needsRehash((new Password('foo'))->hash()))
  ->toBeFalse();

});