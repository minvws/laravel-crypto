<?php

namespace MinVWS\Crypto\Tests\Exception;

use MinVWS\Crypto\Laravel\CryptoException;
use PHPUnit\Framework\TestCase;

class CryptoExceptionTest extends TestCase
{
    /**
     *
     */
    public function testExceptions(): void
    {
        $this->assertEquals('Cannot decrypt data', CryptoException::decrypt()->getMessage());
        $this->assertEquals('Cannot decrypt data: foobar', CryptoException::decrypt("foobar")->getMessage());

        $this->assertEquals('Cannot encrypt data', CryptoException::encrypt()->getMessage());
        $this->assertEquals('Cannot encrypt data: foobar', CryptoException::encrypt("foobar")->getMessage());

        $this->assertEquals('Cannot sign data', CryptoException::sign()->getMessage());
        $this->assertEquals('Cannot sign data: foobar', CryptoException::sign("foobar")->getMessage());

        $this->assertEquals('Cannot verify data', CryptoException::verify()->getMessage());
        $this->assertEquals('Cannot verify data: foobar', CryptoException::verify("foobar")->getMessage());
    }
}
