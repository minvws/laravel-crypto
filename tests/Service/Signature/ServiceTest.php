<?php

namespace MinVWS\Crypto\Tests\Service\Signature;

use MinVWS\Crypto\Laravel\Service\Signature\NativeService;
use MinVWS\Crypto\Laravel\Service\Signature\ProcessSpawnService;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use PHPUnit\Framework\TestCase;

class ServiceTest extends TestCase
{

    public function serviceTypeProvider(): array
    {
        if (PHP_VERSION_ID >= 80000) {
            return array(
                array('native', 'native'),
                array('spawn', 'spawn'),
                array('spawn', 'native'),
                array('native', 'spawn'),
            );
        }

        // php7 only uses spawn
        return array(
            array('spawn', 'spawn'),
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
    }

    /**
     * @dataProvider serviceTypeProvider
     */
    public function testAllPurpose(string $serviceType, string $serviceTypeOther): void
    {
        $data = json_decode(file_get_contents(__DIR__ . "/../../mockdata/mock-signature.json"), true);

        $service = $this->getService($serviceType);
        $this->assertTrue($service->verify($data['signature'], base64_decode($data['payload'])));
    }

    private function getService(string $serviceType): SignatureCryptoInterface
    {
        $args = [
            './tests/mockdata/cert-001.cert',
            './tests/mockdata/cert-001.key',
            '',
            './tests/mockdata/cert-001.chain',
        ];

        if ($serviceType == 'native') {
            return new NativeService(...$args);
        }

        return new ProcessSpawnService(...$args);
    }
}
