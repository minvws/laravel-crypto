<?php

namespace MinVWS\Crypto\Laravel\Tests\Service\Signature;

use MinVWS\Crypto\Laravel\Service\Signature\NativeService;
use MinVWS\Crypto\Laravel\Service\Signature\ProcessSpawnService;
use MinVWS\Crypto\Laravel\Service\Signature\SignatureVerifyConfig;
use MinVWS\Crypto\Laravel\Service\TempFileService;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use MinVWS\Crypto\Laravel\TempFileInterface;
use PHPUnit\Framework\TestCase;

class CorrectAttrTest extends TestCase
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
     */
    public function testCorrectNotdetached(string $serviceType, string $serviceTypeOther): void
    {
        $service = $this->getServiceWithAttrCertificate($serviceType);
        $serviceOther = $this->getServiceWithAttrCertificate($serviceTypeOther);

        $signedData = $service->sign('foobar');
        $this->assertTrue($serviceOther->verify($signedData));
        $this->assertTrue(
            $serviceOther->verify(
                $signedData,
                null,
                file_get_contents('./tests/mockdata/attr.example.org.cert.pem'),
                (new SignatureVerifyConfig())->setNoVerify(true),
            )
        );
        $this->assertTrue(
            $serviceOther->verify($signedData, null, file_get_contents('./tests/mockdata/attr.example.org.cert.pem'))
        );
        $this->assertFalse(
            $serviceOther->verify($signedData, null, file_get_contents('./tests/mockdata/cert-002.cert'))
        );
        $this->assertFalse(
            $serviceOther->verify(
                $signedData,
                null,
                file_get_contents('./tests/mockdata/cert-002.cert'),
                (new SignatureVerifyConfig())->setNoVerify(true),
            )
        );
    }

    /**
     * @dataProvider serviceTypeProvider
     */
    public function testCorrectDetached(string $serviceType, string $serviceTypeOther): void
    {
        $service = $this->getServiceWithAttrCertificate($serviceType);
        $serviceOther = $this->getServiceWithAttrCertificate($serviceTypeOther);

        $signedData = $service->sign('foobar', true);
        $this->assertTrue($serviceOther->verify($signedData, 'foobar'));
        $this->assertFalse($serviceOther->verify($signedData, 'not-foobar'));
        $this->assertFalse($serviceOther->verify($signedData));
        $this->assertTrue(
            $serviceOther->verify($signedData, 'foobar', null, (new SignatureVerifyConfig())->setNoVerify(true))
        );
        $this->assertFalse(
            $serviceOther->verify($signedData, 'not-foobar', null, (new SignatureVerifyConfig())->setNoVerify(true))
        );

        $this->assertTrue(
            $serviceOther->verify(
                $signedData,
                'foobar',
                file_get_contents('./tests/mockdata/attr.example.org.cert.pem')
            )
        );
        $this->assertTrue(
            $serviceOther->verify(
                $signedData,
                'foobar',
                file_get_contents('./tests/mockdata/attr.example.org.cert.pem'),
                (new SignatureVerifyConfig())->setNoVerify(true)
            )
        );
        $this->assertFalse(
            $serviceOther->verify($signedData, 'foobar', file_get_contents('./tests/mockdata/cert-002.cert'))
        );
        $this->assertFalse(
            $serviceOther->verify(
                $signedData,
                'foobar',
                file_get_contents('./tests/mockdata/cert-002.cert'),
                (new SignatureVerifyConfig())->setNoVerify(true),
            )
        );
    }

    /**
     * @dataProvider serviceTypeProvider
     */
    public function testCorrectDetachedWithoutChain(string $serviceType, string $serviceTypeOther): void
    {
        $service = $this->getServiceWithAttrCertificate($serviceType, false);
        $serviceOther = $this->getServiceWithAttrCertificate($serviceTypeOther, false);

        $signedData = $service->sign('foobar', true);
        $this->assertFalse($serviceOther->verify($signedData, 'foobar'));
        $this->assertFalse($serviceOther->verify($signedData, 'not-foobar'));
        $this->assertFalse($serviceOther->verify($signedData));
        $this->assertTrue(
            $serviceOther->verify(
                $signedData,
                'foobar',
                null,
                (new SignatureVerifyConfig())->setNoVerify(true),
            )
        );
        $this->assertFalse(
            $serviceOther->verify(
                $signedData,
                'not-foobar',
                null,
                (new SignatureVerifyConfig())->setNoVerify(true)
            )
        );

        $this->assertTrue(
            $serviceOther->verify(
                $signedData,
                'foobar',
                file_get_contents('./tests/mockdata/attr.example.org.cert.pem'),
                (new SignatureVerifyConfig())->setNoVerify(true),
            )
        );
        $this->assertFalse(
            $serviceOther->verify(
                $signedData,
                'foobar',
                file_get_contents('./tests/mockdata/attr.example.org.cert.pem')
            )
        );
        $this->assertFalse(
            $serviceOther->verify(
                $signedData,
                'foobar',
                file_get_contents('./tests/mockdata/cert-002.cert')
            )
        );
        $this->assertFalse(
            $serviceOther->verify(
                $signedData,
                'foobar',
                file_get_contents('./tests/mockdata/cert-002.cert'),
                (new SignatureVerifyConfig())->setNoVerify(true),
            )
        );
    }

    private function getServiceWithAttrCertificate(
        string $serviceType,
        bool $withChain = true,
    ): SignatureCryptoInterface {
        $args = [
            './tests/mockdata/attr.example.org.cert.pem',
            './tests/mockdata/attr.example.org.key.pem',
            '',
            $withChain ? './tests/mockdata/example.org.chain.pem' : null,
            new TempFileService()
        ];

        if ($serviceType === 'native') {
            return new NativeService(...$args);
        }

        return new ProcessSpawnService(...$args);
    }
}
