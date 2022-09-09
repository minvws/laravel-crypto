<?php

namespace MinVWS\Crypto\Laravel\Tests\Service\Cms;

use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\Service\Cms\NativeService;
use MinVWS\Crypto\Laravel\Service\Cms\ProcessSpawnService;
use MinVWS\Crypto\Laravel\CmsCryptoInterface;
use MinVWS\Crypto\Laravel\Service\TempFileService;
use PHPUnit\Framework\TestCase;

class ServiceTest extends TestCase
{
    public function serviceTypeProvider(): array
    {
        return array(
            array('native', 'native'),
            array('spawn', 'spawn'),
            array('spawn', 'native'),
            array('native', 'spawn'),
        );
    }

    /**
     * @dataProvider serviceTypeProvider
     * @param string $serviceType
     * @param string $serviceTypeOther
     */
    public function testCorrect(string $serviceType, string $serviceTypeOther): void
    {
        $service = $this->getService($serviceType, null, null);
        $serviceOther = $this->getService($serviceTypeOther, null, null);

        $plainText = 'foobar';
        $this->assertEquals($plainText, $serviceOther->decrypt($service->encrypt($plainText)));
    }

    /**
     * @dataProvider serviceTypeProvider
     * @param string $serviceType
     * @param string $serviceTypeOther
     */
    public function testIncorrectCert(string $serviceType, string $serviceTypeOther): void
    {
        $service = $this->getService($serviceType, null, null);
        $serviceOther = $this->getService($serviceTypeOther, null, null);

        $plainText = 'foobar';
        $cipherText = $service->encrypt($plainText);

        $service = $this->getService(
            $serviceTypeOther,
            $this->certPath('cert-001.cert'),
            $this->certPath('cert-001.key')
        );
        $this->assertEquals($plainText, $service->decrypt($cipherText));
        $service = $this->getService(
            $serviceTypeOther,
            $this->certPath('cert-002.cert'),
            $this->certPath('cert-002.key')
        );
        $this->assertEquals($plainText, $service->decrypt($cipherText));

        // Cert 3 is not used for encryption, it should fail
        $this->expectException(CryptoException::class);
        $service = $this->getService(
            $serviceTypeOther,
            $this->certPath('cert-003.cert'),
            $this->certPath('cert-003.key')
        );
        $service->decrypt($cipherText);
    }

    /**
     * @param string $serviceType
     * @param string|null $decryptCert
     * @param string|null $decryptCertkey
     * @return CmsCryptoInterface
     */
    private function getService(string $serviceType, ?string $decryptCert, ?string $decryptCertkey): CmsCryptoInterface
    {
        $encryptCerts = [
            $this->certPath('cert-001.cert'),
            $this->certPath('cert-002.cert'),
        ];

        $args = [
            $encryptCerts,
            $decryptCert ?? $this->certPath('cert-002.cert'),
            $decryptCertkey ?? $this->certPath('cert-002.key'),
            new TempFileService()
        ];

        if ($serviceType == 'native') {
            return new NativeService(...$args);
        }

        return new ProcessSpawnService(...$args);
    }

    /**
     * @param string $file
     * @return string
     */
    private function certPath(string $file): string
    {
        return realpath(__DIR__ . '/../../mockdata/' . $file);
    }
}
