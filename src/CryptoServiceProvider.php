<?php

namespace MinVWS\Crypto\Laravel;

use MinVWS\Crypto\Laravel\Service\Sealbox;
use MinVWS\Crypto\Laravel\Service\Cms;
use MinVWS\Crypto\Laravel\Service\Signature;
use Illuminate\Support\ServiceProvider;
use MinVWS\Crypto\Laravel\Service\TempFileService;

class CryptoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/crypto.php', 'crypto');

        $this->app->bind(TempFileInterface::class, TempFileService::class);

        $this->app->singleton(CmsCryptoInterface::class, function () {
            if (function_exists('openssl_cms_encrypt')) {
                return new Cms\NativeService(
                    config('crypto.cms.encryption_certificate_paths', []),
                    config('crypto.cms.decryption_certificate_path'),
                    config('crypto.cms.decryption_certificate_key_path'),
                    app(TempFileInterface::class),
                );
            }

            return new Cms\ProcessSpawnService(
                config('crypto.cms.encryption_certificate_paths', []),
                config('crypto.cms.decryption_certificate_path'),
                config('crypto.cms.decryption_certificate_key_path'),
            );
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
                app(TempFileInterface::class),
            ];

            if (function_exists('openssl_cms_sign')) {
                return new Signature\NativeService(...$args);
            }

            return new Signature\ProcessSpawnService(...$args);
        });

        $this->app->singleton(SignatureVerifyCryptoInterface::class, function () {
            if (function_exists('openssl_cms_verify')) {
                return new Signature\NativeService(tempFileService: app(TempFileInterface::class));
            } else {
                return new Signature\ProcessSpawnService(tempFileService: app(TempFileInterface::class));
            }
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/crypto.php' => config_path('crypto.php'),
            ], 'crypto');
        }
    }
}
