<?php

use scrothers\laravelsodium\SodiumEncrypter;

class EncrypterTest extends PHPUnit_Framework_TestCase
{
    /**
     * @requires extension libsodium
     */
    public function testSodiumEncryption()
    {
        $e = new SodiumEncrypter(str_repeat('a', 16));
        $encrypted = $e->encrypt('foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }
}
