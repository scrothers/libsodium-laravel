<?php

use scrothers\laravelsodium\SodiumLibrary;

class LibraryTest extends PHPUnit_Framework_TestCase
{
    /**
     * @requires                 extension libsodium
     * @expectedException        scrothers\laravelsodium\Exceptions\KeyTypeException
     * @expectedExceptionMessage keyedHash expects a string as the key
     */
    public function testSodiumKeyedHashBadKey()
    {
        SodiumLibrary::keyedHash('foo', 1);
    }

    /**
     * @requires                       extension libsodium
     * @expectedException              scrothers\laravelsodium\Exceptions\HashLengthException
     * @expectedExceptionMessageRegExp #Hash length should be between \d+ and \d+#
     */
    public function testSodiumRawHashLengthBounds()
    {
        SodiumLibrary::rawHash('foo', null, 1);
    }

    /**
     * @requires extension libsodium
     */
    public function testSodiumPubPrivMessageEncryption()
    {
        $Adam = SodiumLibrary::genBoxKeypair();
        $Eve = SodiumLibrary::genBoxKeypair();
        $encryptedMessage = SodiumLibrary::messageSendEncrypt($Adam['pub'], $Eve['pri'], 'message');
        $this->assertEquals('message', SodiumLibrary::messageReceiveEncrypt($Adam['pri'], $Eve['pub'], $encryptedMessage));
    }

    /**
     * @requires extension libsodium
     */
    public function testSodiumMessageSigning()
    {
        $Adam = SodiumLibrary::genSignKeypair();
        $Eve = SodiumLibrary::genSignKeypair();
        $signedMessage = SodiumLibrary::signMessage($Adam['pri'], 'message');
        $this->assertEquals('message', SodiumLibrary::verifySignature($Adam['pub'], $signedMessage));
    }
}
