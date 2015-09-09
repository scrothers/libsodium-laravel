<?php

use scrothers\laravelsodium\SodiumHasher;

class HasherTest extends PHPUnit_Framework_TestCase
{
    /**
     * @requires extension libsodium
     */
    public function testBasicHashing()
    {
        $hasher = new SodiumHasher();
        $value = $hasher->make('password');
        $this->assertNotSame('password', $value);
        $this->assertTrue($hasher->check('password', $value));
        $this->assertFalse($hasher->needsRehash($value));
    }

    /**
     * @requires extension libsodium
     */
    public function testSlowHashing()
    {
        $hasher = new SodiumHasher();
        $value = $hasher->make('password', ['slow' => true]);
        $this->assertNotSame('password', $value);
        $this->assertTrue($hasher->check('password', $value));
        $this->assertFalse($hasher->needsRehash($value));
    }
}
