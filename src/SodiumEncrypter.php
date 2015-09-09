<?php

namespace scrothers\laravelsodium;

use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Encryption\BaseEncrypter;

class SodiumEncrypter extends BaseEncrypter implements EncrypterContract
{
    /**
     * Create a new encrypter instance.
     *
     * @param string $key
     */
    public function __construct($key)
    {
        $this->key = $key;
    }

    /**
     * Encrypt the given value.
     *
     * @param string $value
     *
     * @return string
     */
    public function encrypt($value)
    {
        return SodiumLibrary::encrypt($value, $this->key);
    }

    /**
     * Decrypt the given value.
     *
     * @param string $payload
     *
     * @return string
     */
    public function decrypt($payload)
    {
        return SodiumLibrary::decrypt($payload, $this->key);
    }
}
