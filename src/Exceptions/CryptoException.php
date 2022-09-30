<?php

namespace MinVWS\Crypto\Laravel\Exceptions;

class CryptoException extends \RuntimeException
{
    public static function encrypt(string $msg = ""): CryptoException
    {
        if (! empty($msg)) {
            $msg = ": " . $msg;
        }

        return new self("cannot encrypt data" . $msg);
    }

    public static function decrypt(string $msg = ""): CryptoException
    {
        if (! empty($msg)) {
            $msg = ": " . $msg;
        }

        return new self("cannot decrypt data" . $msg);
    }

    public static function sign(string $msg = ""): CryptoException
    {
        if (! empty($msg)) {
            $msg = ": " . $msg;
        }

        return new self("cannot sign data" . $msg);
    }

    public static function verify(string $msg = ""): CryptoException
    {
        if (! empty($msg)) {
            $msg = ": " . $msg;
        }

        return new self("cannot verify data" . $msg);
    }

    public static function cannotReadFile(?string $path): CryptoException
    {
        if (!$path) {
            return new self(sprintf("no keyfile has been specified"));
        }

        return new self(sprintf("error while reading keyfile %s: file is not readable by user (try chmod 644)", $path));
    }
}
