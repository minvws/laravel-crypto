<?php

namespace MinVWS\Crypto\Laravel\Tests\Http\Middleware;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use MinVWS\Crypto\Laravel\Http\Middleware\CmsSignature;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use Mockery;
use PHPUnit\Framework\TestCase;

class CmsSignatureTest extends TestCase
{
    /**
     *
     */
    public function testSignatureButNotAdded(): void
    {
        $request = new Request();
        $next = function (Request $request) {
            return new Response("foobar", 200);
        };

        $mock = Mockery::mock(SignatureCryptoInterface::class);
        $mock->shouldReceive('sign')->andReturn('SIGDATA');

        $middleware = new CmsSignature($mock, CmsSignature::FORMAT_NONE);
        $response = $middleware->handle($request, $next);

        $this->assertEquals('False', $response->headers->get('x-cms-signed'));
    }

    public function testSignatureButAndAddedInlineWithJson(): void
    {
        $request = new Request();
        $next = function (Request $request) {
            return new JsonResponse(["foo" => "bar"], 200);
        };

        $mock = Mockery::mock(SignatureCryptoInterface::class);
        $mock->shouldReceive('sign')->andReturn('SIGDATA');

        $middleware = new CmsSignature($mock, CmsSignature::FORMAT_INLINE);
        $response = $middleware->handle($request, $next);

        $this->assertEquals('True', $response->headers->get('x-cms-signed'));
        $this->assertEquals([
            'signature' => 'SIGDATA',
            'payload' => 'eyJmb28iOiJiYXIifQ==',
        ], $response->getData(true));
    }

    public function testSignatureButAndAddedInlineWithoutJson(): void
    {
        $request = new Request();
        $next = function (Request $request) {
            return new Response("foobar-no-json", 200);
        };

        $mock = Mockery::mock(SignatureCryptoInterface::class);
        $mock->shouldReceive('sign')->andReturns('SIGDATA');

        $middleware = new CmsSignature($mock, CmsSignature::FORMAT_INLINE);
        $response = $middleware->handle($request, $next);

        $this->assertEquals('False', $response->headers->get('x-cms-signed'));
    }
}
