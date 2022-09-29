<?php

namespace MinVWS\Crypto\Laravel;

use Illuminate\Support\ServiceProvider;
use MinVWS\Crypto\Laravel\Service\TempFileService;

class CryptoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/crypto.php', 'crypto');

        $this->app->bind(TempFileInterface::class, TempFileService::class);

        $this->app->singleton(CmsCryptoInterface::class, function () {
            Factory::createCmsCryptoService(
                encryptionCertPaths: config('crypto.cms.encryption_certificate_paths'),
                decryptionCertPath: config('crypto.cms.decryption_certificate_path'),
                decryptionKeyPath: config('crypto.cms.decryption_certificate_key_path'),
                forceProcessSpawn: config('crypto.force_process_spawn', false),
            );
        });

        $this->app->singleton(SealboxCryptoInterface::class, function () {
            Factory::createSealboxCryptoService(
                privKey: config('crypto.sealbox.private_key'),
                recipientPubKey: config('crypto.sealbox.recipient_pub_key'),
            );
        });

        $this->app->singleton(SignatureCryptoInterface::class, function () {
            Factory::createSignatureCryptoService(
                certificatePath: config('crypto.signature.x509_cert'),
                certificateKeyPath: config('crypto.signature.x509_key'),
                certificateKeyPass: config('crypto.signature.x509_pass'),
                certificateChain: config('crypto.signature.x509_chain'),
                forceProcessSpawn: config('crypto.force_process_spawn', false),
            );
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
