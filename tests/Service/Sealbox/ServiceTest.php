<?php

namespace MinVWS\Crypto\Laravel\Tests\Service\Sealbox;

use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\SealboxCryptoInterface;
use MinVWS\Crypto\Laravel\Service\Sealbox\SealboxService;
use PHPUnit\Framework\TestCase;

class ServiceTest extends TestCase
{
    protected const TEST_PRIVKEY = '/BmJGKHzacb8/aZYl5d1dwjJd7kcv6SLxux7A8Ld5Hk=';
    protected const TEST_PUBKEY = 'iUDWI5RkuUVQQAaC4BoYFdZXP7Lod6RTL9orQeuRzxE=';

    public function testCorrect(): void
    {
        $service = $this->getService();

        $plainText = 'foobar';
        $this->assertEquals($plainText, $service->decrypt($service->encrypt($plainText)));
    }

    public function testIncorrectPubKey(): void
    {
        $service = $this->getService(null, 'egadsgdsagsadgsadgasgsagagaod6RTL9orQeuRzxE=');

        $this->expectException(CryptoException::class);

        $plainText = 'foobar';
        $service->decrypt($service->encrypt($plainText));
    }

    /**
     * @param string $privKey
     * @param string $pubKey
     * @return SealboxCryptoInterface
     * @throws \SodiumException
     */
    private function getService(?string $privKey = null, ?string $pubKey = null): SealboxCryptoInterface
    {
        return new SealboxService($privKey ?? self::TEST_PRIVKEY, $pubKey ?? self::TEST_PUBKEY);
    }
}
