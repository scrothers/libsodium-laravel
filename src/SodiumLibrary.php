<?php


namespace scrothers\laravelsodium;

use Sodium;
use scrothers\laravelsodium\Exceptions\DecryptionException;
use scrothers\laravelsodium\Exceptions\HashLengthException;
use scrothers\laravelsodium\Exceptions\KeyTypeException;

class SodiumLibrary
{
    /**
     * Return an amount of binary entropy
     *
     * @param int $amount The amount of entropy you want to generate
     * @return string
     */
    public static function entropy($amount = Sodium\CRYPTO_SECRETBOX_NONCEBYTES)
    {
        return Sodium\randombytes_buf($amount);
    }

    /**
     * Return a hexadecimal string from binary
     *
     * @param string $hexString The hexadecimal string being converted to binary
     * @return string
     */
    public static function bin2hex($hexString)
    {
        return Sodium\bin2hex($hexString);
    }

    /**
     * Return a binary string from hexadecimal
     *
     * @param string $binString The binary string being converted to hexadecimal
     * @param string $ignore Characters to ignore in the hexadecimal string
     * @return string
     */
    public static function hex2bin($binString, $ignore = '')
    {
        return Sodium\hex2bin($binString, $ignore);
    }

    /**
     * Wipe a variable from PHP's memory
     *
     * @param $variable
     * @return void
     */
    public static function wipeMemory($variable)
    {
        Sodium\memzero($variable);
    }

    /**
     * The raw hash method simply hashes a string with specific options with Sodium
     *
     * @param string $data The message to be hashed
     * @param string $key The key to hash the data to
     * @param int $length The length of the cache to be returned
     * @return string
     */
    private static function rawHash($data, $key = null, $length = Sodium\CRYPTO_GENERICHASH_BYTES)
    {
        # Test to make sure the length is within bounds
        if (!($length >= Sodium\CRYPTO_GENERICHASH_BYTES_MIN && $length <= Sodium\CRYPTO_GENERICHASH_BYTES_MAX)) {
            throw new HashLengthException(sprintf('Hash length should be between %s and %s',
                Sodium\CRYPTO_GENERICHASH_BYTES_MIN,
                Sodium\CRYPTO_GENERICHASH_BYTES_MAX
            ));
        }

        # Test if a key is set, if it is, generate a key if true, or use a key if set
        if ($key !== null) {
            if ($key === true) {
                $key = Sodium\randombytes_buf(Sodium\CRYPTO_GENERICHASH_KEYBYTES_MAX);
            } else {
                $key = self::rawHash($key);
            }
        }

        return Sodium\crypto_generichash($data, $key, $length);
    }

    /**
     * A drop in replacement for md5() hashing
     *
     * @param string $data The data to be hashed
     * @return string
     */
    public static function hash($data)
    {
        return self::rawHash($data, null, Sodium\CRYPTO_GENERICHASH_BYTES_MIN);
    }

    /**
     * A longer more secure hash with less chance of collision
     *
     * @param string $data The data to be hashed
     * @return string
     */
    public static function secureHash($data)
    {
        return self::rawHash($data);
    }

    /**
     * A very long hash which is designed to be very unique with the least chance of collision
     *
     * @param string $data The data to be hashed
     * @return string
     */
    public static function veryUniqueHash($data)
    {
        return self::rawHash($data, null, Sodium\CRYPTO_GENERICHASH_BYTES_MAX);
    }

    /**
     * The keyedHash method hashes a message with a key for salt, requiring verification to know the key
     *
     * @param string $data The data to be hashed
     * @param string $key The key to hash the data against
     * @param int $length The length of the hash to generate, defaults to Sodium\CRYPTO_GENERICHASH_BYTES
     * @return string
     */
    public static function keyedHash($data, $key, $length = Sodium\CRYPTO_GENERICHASH_BYTES)
    {
        # Test to make sure the key is a string
        if (!is_string($key)) {
            throw new KeyTypeException('keyedHash expects a string as the key');
        }

        return self::rawHash($data, $key, $length);
    }

    /**
     * Hash a password using Sodium for later verification, optionally add slowness
     *
     * @param string $plaintext The plaintext password to be hashed
     * @param bool|false $extraSecure Add additional slowness to the hashing technique for security
     * @return string
     */
    public static function hashPassword($plaintext, $extraSecure = false)
    {
        # Create the password hash
        if ($extraSecure) {
            $passwordHash = Sodium\crypto_pwhash_scryptsalsa208sha256_str(
                $plaintext,
                Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE,
                Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE
            );
        } else {
            $passwordHash = Sodium\crypto_pwhash_scryptsalsa208sha256_str(
                $plaintext,
                Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
            );
        }

        return $passwordHash;
    }

    /**
     * Verify if a password is correct by matching a plaintext password to a hash
     *
     * @param string $password
     * @param string $hash
     * @return bool
     */
    public static function checkPassword($password, $hash)
    {
        if (Sodium\crypto_pwhash_scryptsalsa208sha256_str_verify($hash, $password)) {
            self::wipeMemory($password);

            return true;
        }
        self::wipeMemory($password);

        return false;
    }

    /**
     * Encrypt a message using a key
     *
     * @param string $message A message in string format
     * @param string $key A binary hashed key
     * @return string
     */
    public static function encrypt($message, $key)
    {
        # Generate entropy to encrypt the data
        $nonce = self::entropy();

        # Encrypt the message
        $messageEncrypted = Sodium\crypto_secretbox($message, $nonce, self::rawHash($key, null, Sodium\CRYPTO_SECRETBOX_KEYBYTES));

        return sprintf('%s.%s', self::bin2hex($nonce), self::bin2hex($messageEncrypted));
    }

    /**
     * Decrypt a message using a key
     *
     * @param string $message
     * @param string $key
     * @return mixed
     */
    public static function decrypt($message, $key)
    {
        $payload = explode('.', $message);

        $decryption = Sodium\crypto_secretbox_open(
            Sodium\hex2bin($payload[1]),
            Sodium\hex2bin($payload[0]),
            self::rawHash($key, null, Sodium\CRYPTO_SECRETBOX_KEYBYTES)
        );

        if (!$decryption) {
            throw new DecryptionException('The key provided cannot decrypt the message');
        }

        return $decryption;
    }
}