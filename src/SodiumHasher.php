<?php


namespace scrothers\laravelsodium;

use Illuminate\Contracts\Hashing\Hasher as HasherContract;

class SodiumHasher implements HasherContract
{
    /**
     * Check if the given hash has been hashed using the given options.
     *
     * @param string $unusedHashedValue
     * @param array $unusedOptions
     * @return bool
     */
    public function needsRehash($unusedHashedValue, array $unusedOptions = [])
    {
        return false;
    }
    /**
     * Hash the given value.
     *
     * @param string $value
     * @param array $options
     * @return string
     *
     * @throws \RuntimeException
     *
     * @return string
     */
    public function make($value, array $options = [])
    {
        # Check if we're making a slow password
        if (array_key_exists('slow', $options)) {
            if (is_bool($options['slow'])) {
                $slowPassword = $options['slow'];
            } else {
                $slowPassword = false;
            }
        } else {
            $slowPassword = false;
        }

        return SodiumLibrary::hashPassword($value, $slowPassword);
    }
    /**
     * Check the given plain value against a hash.
     *
     * @param string $value
     * @param string $hashedValue
     * @param array $unusedOptions Options are not used for Sodium password verification
     *
     * @return bool
     */
    public function check($value, $hashedValue, array $unusedOptions = [])
    {
        return SodiumLibrary::checkPassword($value, $hashedValue);
    }
}
