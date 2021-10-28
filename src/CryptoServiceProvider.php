<?php

namespace MinVWS\Crypto\Laravel;

use MinVWS\Crypto\Laravel\Service\Sealbox;
use MinVWS\Crypto\Laravel\Service\Cms;
use MinVWS\Crypto\Laravel\Service\Signature;
use Illuminate\Support\ServiceProvider;

class CryptoServiceProvider extends ServiceProvider
{
    /**
     * @returns void
     * @throws \SodiumException
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/crypto.php', 'crypto');

        $this->app->singleton(CmsCryptoInterface::class, function () {
            $args = [
                config('crypto.cms.encryption_certificate_paths', []),
                config('crypto.cms.decryption_certificate_path'),
                config('crypto.cms.decryption_certificate_key_path'),
            ];

            if (function_exists('openssl_cms_encrypt')) {
                return new Cms\NativeService(...$args);
            } else {
                return new Cms\ProcessSpawnService(...$args);
            }
        });

        $this->app->singleton(SealboxCryptoInterface::class, function () {
            return new Sealbox\SealboxService(
                config('crypto.sealbox.private_key'),
                config('crypto.sealbox.recipient_public_key')
            );
        });

        $this->app->singleton(SignatureCryptoInterface::class, function () {
            $args = [
                config('crypto.signature.x509_cert'),
                config('crypto.signature.x509_key'),
                config('crypto.signature.x509_pass', ''),
                config('crypto.signature.x509_chain', ''),
            ];
            if (function_exists('openssl_cms_sign')) {
                return new Signature\NativeService(...$args);
            } else {
                return new Signature\ProcessSpawnService(...$args);
            }
        });
    }

    /**
     *
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/crypto.php' => config_path('crypto.php'),
            ], 'crypto');
        }
    }
}
