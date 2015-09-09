<?php

namespace scrothers\laravelsodium\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \scrothers\laravelsodium\SodiumMessaging
 */
class Messaging extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'messaging';
    }
}
