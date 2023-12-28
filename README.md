# What the Framework?! security

## Installation
```bash
composer require wtframework/security
```

## Documentation

### Configuration
Use the [Config](https://github.com/wtframework/config) library to set the security configuration settings.
```php
use WTFramework\Config\Config;

Config::set([
  'security' => [
    'encryption_key' => 'ec5964323dc239ab63417a0f98ff1eef', // openssl rand -hex 16
    'hash_salt' => 'f93101e3a5f4f09f8c1a9ac0f9301c6e', // openssl rand -hex 16
    'password_pepper' => '2429fc585eef890c13e2c5307dcb02f23d8d83ea86740d864a6e79e2a7613cd1a95efd42', // openssl rand -hex 36
  ],
]);
```
\
Settings:

`security`\
The root security setting.

`security.password_pepper`\
The application wide salt to append to every password.

`security.password_algorithm`\
The `password_hash` algorithm. The default is `PASSWORD_DEFAULT`.

`security.password_options`\
The `password_hash` options. The default is `['cost' => 12]`.

`security.encryption_key`\
The `openssl_encrypt` passphrase.

`security.encryption_algorithm`\
The `openssl_encrypt` cipher method. The default is `aes-128-gcm`.

`security.encryption_options`\
The `openssl_encrypt` options. The default is `0`.

`security.hash_salt`\
The `hash_pbkdf2` salt.

`security.hash_algorithm`\
The `hash_pbkdf2` hashing algorithm. The default is `sha3-512`.

`security.hash_iterations`\
The `hash_pbkdf2` iterations. The default is `10000`.

### WTFramework\Security\Password
Hash a password:
```php
use WTFramework\Security\Password;

$hash = Password::hash('password');
```
\
Verify a hashed password:
```php
if (Password::verify('password', $hash))
{
  // ...
}
```
\
Check to see if the password needs to be rehashed:
```php
if (Password::needsRehash($hash))
{
  // ...
}
```

### WTFramework\Security\Crypt
Encrypt text:
```php
use WTFramework\Security\Crypt;

$encrypted = Crypt::encrypt('text');
```
\
Decrypt text:
```php
$text = Crypt::decrypt($encrypted);
```
\
Hash text:
```php
$hashed = Crypt::hash('text');
```
\
Generate a version 4 UUID:
```php
$uuid = Crypt::uuid();
```