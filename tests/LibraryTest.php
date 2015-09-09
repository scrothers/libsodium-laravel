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
}
