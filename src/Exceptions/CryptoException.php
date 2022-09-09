<?php

namespace MinVWS\Crypto\Laravel\Exceptions;

class CryptoException extends \RuntimeException
{
    /**
     * @param string $msg
     * @return CryptoException
     */
    public static function encrypt(string $msg = ""): CryptoException
    {
        if (! empty($msg)) {
            $msg = ": " . $msg;
        }

        return new self("Cannot encrypt data" . $msg);
    }

    /**
     * @param string $msg
     * @return CryptoException
     */
    public static function decrypt(string $msg = ""): CryptoException
    {
        if (! empty($msg)) {
            $msg = ": " . $msg;
        }

        return new self("Cannot decrypt data" . $msg);
    }

    /**
     * @param string $msg
     * @return CryptoException
     */
    public static function sign(string $msg = ""): CryptoException
    {
        if (! empty($msg)) {
            $msg = ": " . $msg;
        }

        return new self("Cannot sign data" . $msg);
    }

    /**
     * @param string $msg
     * @return CryptoException
     */
    public static function verify(string $msg = ""): CryptoException
    {
        if (! empty($msg)) {
            $msg = ": " . $msg;
        }

        return new self("Cannot verify data" . $msg);
    }

    /**
     * @param string $path
     * @return CryptoException
     */
    public static function cannotReadFile(string $path): CryptoException
    {
        return new self(sprintf("Error while reading keyfile %s: file is not readable by user (try chmod 644)", $path));
    }
}
