<?php

namespace MinVWS\Crypto\Laravel\Tests\Service\Signature;

use MinVWS\Crypto\Laravel\Service\Signature\NativeService;
use MinVWS\Crypto\Laravel\Service\Signature\ProcessSpawnService;
use MinVWS\Crypto\Laravel\Service\TempFileService;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use MinVWS\Crypto\Laravel\TempFileInterface;
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
     */
    public function testCorrectNotdetached(string $serviceType, string $serviceTypeOther): void
    {
        $service = $this->getService($serviceType);
        $serviceOther = $this->getService($serviceTypeOther);

        $signedData = $service->sign('foobar');
        $this->assertTrue($serviceOther->verify($signedData));
        $this->assertTrue(
            $serviceOther->verify($signedData, null, file_get_contents('./tests/mockdata/cert-001.cert'))
        );
        $this->assertFalse(
            $serviceOther->verify($signedData, null, file_get_contents('./tests/mockdata/cert-002.cert'))
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
            $serviceOther->verify($signedData, 'foobar', file_get_contents('./tests/mockdata/cert-001.cert'))
        );
        $this->assertFalse(
            $serviceOther->verify($signedData, 'foobar', file_get_contents('./tests/mockdata/cert-002.cert'))
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
}
