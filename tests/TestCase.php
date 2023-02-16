<?php

namespace MinVWS\Crypto\Laravel\Tests;

use MinVWS\Crypto\Laravel\CryptoServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        // additional setup
    }

    protected function getPackageProviders($app): array
    {
        return [
            CryptoServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        // Set sealbox keys
        [$publicKey, $secretKey] = $this->generateSodiumKeys();
        config()->set('crypto.sealbox.recipient_public_key', $publicKey);
        config()->set('crypto.sealbox.private_key', $secretKey);
    }

    protected function generateSodiumKeys(): array
    {
        $keypair = sodium_crypto_box_keypair();

        return [
            base64_encode(sodium_crypto_box_publickey($keypair)),
            base64_encode(sodium_crypto_box_secretkey($keypair)),
        ];
    }
}
