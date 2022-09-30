<?php

namespace MinVWS\Crypto\Laravel\Tests\Exception;

use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use PHPUnit\Framework\TestCase;

class CryptoExceptionTest extends TestCase
{
    /**
     *
     */
    public function testExceptions(): void
    {
        $this->assertEquals('cannot decrypt data', CryptoException::decrypt()->getMessage());
        $this->assertEquals('cannot decrypt data: foobar', CryptoException::decrypt("foobar")->getMessage());

        $this->assertEquals('cannot encrypt data', CryptoException::encrypt()->getMessage());
        $this->assertEquals('cannot encrypt data: foobar', CryptoException::encrypt("foobar")->getMessage());

        $this->assertEquals('cannot sign data', CryptoException::sign()->getMessage());
        $this->assertEquals('cannot sign data: foobar', CryptoException::sign("foobar")->getMessage());

        $this->assertEquals('cannot verify data', CryptoException::verify()->getMessage());
        $this->assertEquals('cannot verify data: foobar', CryptoException::verify("foobar")->getMessage());
    }
}
