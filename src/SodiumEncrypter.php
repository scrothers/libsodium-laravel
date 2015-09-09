<?php


namespace scrothers\laravelsodium;

use Illuminate\Encryption\BaseEncrypter;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;

class SodiumEncrypter extends BaseEncrypter implements EncrypterContract
{
    /**
     * Create a new encrypter instance.
     *
     * @param  string $key
     * @param  string $cipher
     */
    public function __construct($key, $cipher = null)
    {
        $this->key = $key;
    }
    /**
     * Encrypt the given value.
     *
     * @param  string  $value
     * @return string
     */
    public function encrypt($value)
    {
        return SodiumLibrary::encrypt($value, $this->key);
    }
    /**
     * Decrypt the given value.
     *
     * @param  string  $payload
     * @return string
     */
    public function decrypt($payload)
    {
        return SodiumLibrary::decrypt($payload, $this->key);
    }
}
