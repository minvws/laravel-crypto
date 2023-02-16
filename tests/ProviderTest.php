<?php

namespace MinVWS\Crypto\Laravel\Tests;

use MinVWS\Crypto\Laravel\SealboxCryptoInterface;
use MinVWS\Crypto\Laravel\Service\Sealbox\SealboxService;

class ProviderTest extends TestCase
{
    public function testSealboxIsRegisteredCorrectly(): void
    {
        $this->assertInstanceOf(
            SealboxService::class,
            $this->app->make(SealboxCryptoInterface::class)
        );
    }

    public function testDefaultSealboxCanEncryptAndDecrypt(): void
    {
        $sealbox = $this->app->make(SealboxCryptoInterface::class);

        $encrypted = $sealbox->encrypt('foobar');
        $this->assertEquals('foobar', $sealbox->decrypt($encrypted));
    }
}
