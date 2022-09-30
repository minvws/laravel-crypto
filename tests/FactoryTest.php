<?php

namespace MinVWS\Crypto\Laravel\Tests;

use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\Factory;
use MinVWS\Crypto\Laravel\Service\Cms\NativeService;
use MinVWS\Crypto\Laravel\Service\Cms\ProcessSpawnService;
use MinVWS\Crypto\Laravel\CmsCryptoInterface;
use MinVWS\Crypto\Laravel\Service\TempFileService;
use PHPUnit\Framework\TestCase;

class FactoryTest extends TestCase
{
    protected const TEST_PRIVKEY = '/BmJGKHzacb8/aZYl5d1dwjJd7kcv6SLxux7A8Ld5Hk=';
    protected const TEST_PUBKEY = 'iUDWI5RkuUVQQAaC4BoYFdZXP7Lod6RTL9orQeuRzxE=';

    public function boolProvider()
    {
        return array(
            array(true),
            array(false),
        );
    }

    /** @dataProvider boolProvider */
    public function testFactoryCmsCrypto(bool $spawn): void
    {
        $service = Factory::createCmsCryptoService(
            [
                $this->certPath('cert-001.cert'),
                $this->certPath('cert-002.cert'),
            ],
            forceProcessSpawn: $spawn
        );

        $ciphertext = $service->encrypt("foobar");
        $this->assertStringStartsWith('-----BEGIN CMS-----', $ciphertext);

        $service = Factory::createCmsCryptoService(
            [],
            $this->certPath('cert-001.cert'),
            $this->certPath('cert-001.key'),
            forceProcessSpawn: $spawn
        );
        $result = $service->decrypt($ciphertext);
        $this->assertEquals('foobar', $result);

        $service = Factory::createCmsCryptoService(
            [],
            $this->certPath('cert-002.cert'),
            $this->certPath('cert-002.key'),
            forceProcessSpawn: !$spawn          // Decrypt with the other service type (if applicable)
        );
        $result = $service->decrypt($ciphertext);
        $this->assertEquals('foobar', $result);


        $this->expectException(CryptoException::class);

        $service = Factory::createCmsCryptoService(
            [],
            $this->certPath('cert-003.cert'),
            $this->certPath('cert-003.key'),
            forceProcessSpawn: $spawn
        );
        $result = $service->decrypt($ciphertext);
        $this->assertEquals('foobar', $result);
    }

    /** @dataProvider boolProvider */
    public function testCmsCryptoEncodeWitoutCerts(bool $spawn): void
    {
        $service = Factory::createCmsCryptoService(
            [],
            forceProcessSpawn: $spawn
        );

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('cannot encrypt without providing at least one certificate');

        $service->encrypt("foobar");
    }

    /** @dataProvider boolProvider */
    public function testCmsCryptoDecodeWitoutCert(bool $spawn): void
    {
        $service = Factory::createCmsCryptoService(
            [
                $this->certPath('cert-001.cert'),
            ],
            forceProcessSpawn: $spawn
        );
        $ciphertext = $service->encrypt("foobar");


        $service = Factory::createCmsCryptoService(
            [],
            forceProcessSpawn: $spawn
        );

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('cannot decrypt data: no decryption certificate or key provided');

        $service->decrypt($ciphertext);
    }

    public function testFactorySealboxCryptoWithoutKey(): void
    {
        $service = Factory::createSealboxCryptoService(
        );

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('no recipient public key provided');

        $service->encrypt("foobar");
    }

    public function testFactorySealboxCrypto(): void
    {
        $service = Factory::createSealboxCryptoService(
            null,
            self::TEST_PUBKEY
        );

        $ciphertext = $service->encrypt("foobar");
        $this->assertNotEquals('foobar', $ciphertext);

        $service = Factory::createSealboxCryptoService(
            self::TEST_PRIVKEY,
            self::TEST_PUBKEY
        );

        $result = $service->decrypt($ciphertext);
        $this->assertEquals('foobar', $result);
    }

    private function certPath(string $file): string
    {
        return realpath(__DIR__ . '/mockdata/' . $file);
    }
}
