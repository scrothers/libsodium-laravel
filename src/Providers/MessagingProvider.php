<?php

namespace scrothers\laravelsodium\Providers;

use Illuminate\Support\ServiceProvider;
use scrothers\laravelsodium\SodiumMessaging;

class MessagingProvider extends ServiceProvider
{
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('messaging', function () { return new SodiumMessaging(); });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return ['messaging'];
    }
}
