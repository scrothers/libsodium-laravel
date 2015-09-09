<?php


namespace scrothers\laravelsodium\Providers;

use scrothers\laravelsodium\SodiumEncrypter;
use Illuminate\Support\ServiceProvider;

class EncryptionProvider extends ServiceProvider
{
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('encrypter', function ($app) {
            $config = $app->make('config')->get('app');
            $key = $config['key'];

            return new SodiumEncrypter($key);
        });
    }
}
