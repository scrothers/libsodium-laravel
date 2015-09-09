# Libsodium for Laravel
--
This library is meant to be a fairly expansive encryption replacement to Laravel's built in methods. The goals is that by default it will replace the encryption and the hashing mechanisms of Laravel with compatible methods powered by libsodium.

## How to Install
First thing you need to do is install the components you want to replace in Laravel in your `app.cfg` file from your config directory.

### Sodium Encrypter Install
In `app.cfg` replace `Illuminate\Encryption\EncryptionServiceProvider::class` with `scrothers\laravelsodium\Providers\EncryptionProvider::class`.

### Sodium Hasher Install
In `app.cfg` replace `Illuminate\Hashing\HashServiceProvider::class` with `scrothers\laravelsodium\Providers\HashProvider::class`.

## About Sodium
The original Sodium project can be located [here](https://github.com/jedisct1/libsodium), the about Sodium is obtained from the readme in the source repository.

Sodium is a new, easy-to-use software library for encryption,
decryption, signatures, password hashing and more.

It is a portable, cross-compilable, installable, packageable
fork of [NaCl](http://nacl.cr.yp.to/), with a compatible API, and an
extended API to improve usability even further.

Its goal is to provide all of the core operations needed to build
higher-level cryptographic tools.

Sodium supports a variety of compilers and operating systems,
including Windows (with MingW or Visual Studio, x86 and x64), iOS and Android.
