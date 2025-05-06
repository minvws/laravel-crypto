<?php

namespace MinVWS\Crypto\Laravel\Tests\Service\Signature;

use MinVWS\Crypto\Laravel\Service\Signature\NativeService;
use MinVWS\Crypto\Laravel\Service\Signature\ProcessSpawnService;
use MinVWS\Crypto\Laravel\Service\Signature\SignatureVerifyConfig;
use MinVWS\Crypto\Laravel\Service\TempFileService;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use MinVWS\Crypto\Laravel\TempFileInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;

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
     */
    public function testSignatureContainsChain(string $serviceType, string $serviceTypeOther): void
    {
        $service = $this->getService($serviceType);
        $serviceOther = $this->getService($serviceTypeOther);

        $signedData = $service->sign('foobar', true);
        $signedDataByOtherService = $serviceOther->sign('foobar', true);

        $certificatesInSignature = $this->getCertificatesFromSignature($signedData);
        $certificatesInSignatureOtherService = $this->getCertificatesFromSignature($signedDataByOtherService);

        // Check if the created signature both contains same certificates
        $this->assertEquals($certificatesInSignature, $certificatesInSignatureOtherService);

        // Check if the created signature both contains the cert
        $this->assertStringContainsString(
            "subject=C=NL, ST=ZH, L=Den Haag, O=MinVWS, OU=RDO-TESTING, CN=server1.test",
            $certificatesInSignature
        );

        // Check if the created signature both contains the chain
        $this->assertStringContainsString(
            "subject=C=NL, ST=ZH, L=Den Haag, O=MinVWS, OU=RDO-TESTING, CN=RDO-TESTING",
            $certificatesInSignature
        );
    }

    /**
     * @dataProvider serviceTypeProvider
     */
    public function testCorrectNotdetached(string $serviceType, string $serviceTypeOther): void
    {
        $service = $this->getService($serviceType);
        $serviceOther = $this->getService($serviceTypeOther);

        $signedData = $service->sign('foobar');
        $this->assertTrue($serviceOther->verify($signedData));
        $this->assertTrue(
            $serviceOther->verify(
                $signedData,
                null,
                file_get_contents('./tests/mockdata/cert-001.cert'),
                (new SignatureVerifyConfig())->setNoVerify(true),
            )
        );
        $this->assertTrue(
            $serviceOther->verify($signedData, null, file_get_contents('./tests/mockdata/cert-001.cert'))
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
        $service = $this->getService($serviceType);
        $serviceOther = $this->getService($serviceTypeOther);

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
            $serviceOther->verify($signedData, 'foobar', file_get_contents('./tests/mockdata/cert-001.cert'))
        );
        $this->assertTrue(
            $serviceOther->verify(
                $signedData,
                'foobar',
                file_get_contents('./tests/mockdata/cert-001.cert'),
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
        $service = $this->getService($serviceType);
        $serviceOther = $this->getServiceWithoutChain($serviceTypeOther);

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
                file_get_contents('./tests/mockdata/cert-001.cert'),
                (new SignatureVerifyConfig())->setNoVerify(true),
            )
        );
        $this->assertFalse(
            $serviceOther->verify($signedData, 'foobar', file_get_contents('./tests/mockdata/cert-001.cert'))
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

    private function getService(string $serviceType): SignatureCryptoInterface
    {
        $args = [
            './tests/mockdata/cert-001.cert',
            './tests/mockdata/cert-001.key',
            '',
            './tests/mockdata/cert-001.chain',
            new TempFileService()
        ];

        if ($serviceType === 'native') {
            return new NativeService(...$args);
        }

        return new ProcessSpawnService(...$args);
    }

    private function getServiceWithoutChain(string $serviceType): SignatureCryptoInterface
    {
        $args = [
            './tests/mockdata/cert-001.cert',
            './tests/mockdata/cert-001.key',
            '',
            '',
            new TempFileService()
        ];

        if ($serviceType === 'native') {
            return new NativeService(...$args);
        }

        return new ProcessSpawnService(...$args);
    }

    private function getCertificatesFromSignature(string $signature): string
    {
        $process = new Process([
            'openssl', 'pkcs7', '-inform', 'DER', '-print_certs'
        ]);
        $process->setInput(base64_decode($signature));
        $process->run();

        return $process->getOutput();
    }
}
