<?php

declare(strict_types=1);

use WTFramework\Config\Config;
use WTFramework\Security\Crypt;

beforeAll(function ()
{

  Config::set([
    'security' => [
      'encryption_key' => bin2hex(random_bytes(16)),
      'hash_salt' => bin2hex(random_bytes(16)),
    ],
  ]);

});

it('can encrypt', function ()
{

  expect(Crypt::encrypt('foo'))
  ->not()->toEqual('foo');

});

it('can decrypt', function ()
{

  expect(Crypt::decrypt(Crypt::encrypt('foo')))
  ->toEqual('foo');

});

it('can hash', function ()
{

  expect(Crypt::hash('foo'))
  ->not()->toEqual('foo');

});

it('can get uuid', function ()
{

  expect(Crypt::uuid())
  ->toMatch(
    '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/'
  );

});