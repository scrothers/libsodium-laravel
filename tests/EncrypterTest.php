<?php

use scrothers\laravelsodium\SodiumEncrypter;
use scrothers\laravelsodium\SodiumLibrary;

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

    /**
     * @requires                 extension libsodium
     * @expectedException        scrothers\laravelsodium\Exceptions\DecryptionException
     * @expectedExceptionMessage The key provided cannot decrypt the message
     */
    public function testSodiumEncryptionFail()
    {
        $encrypted = SodiumLibrary::encrypt('foo', str_repeat('a', 16));
        SodiumLibrary::decrypt($encrypted, str_repeat('b', 16));
    }
}
