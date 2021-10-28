<?php

namespace MinVWS\Crypto\Laravel;

class CryptoException extends \RuntimeException
{
    /**
     * @param string $msg
     * @return CryptoException
     */
    public static function encrypt(string $msg = "")
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
    public static function decrypt(string $msg = "")
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
    public static function sign(string $msg = "")
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
    public static function verify(string $msg = "")
    {
        if (! empty($msg)) {
            $msg = ": " . $msg;
        }

        return new self("Cannot verify data" . $msg);
    }

    /**
     * @return CryptoException
     */
    public static function encryptCannotCreateTempFile()
    {
        return self::encrypt("cannot create temp file on disk");
    }

    /**
     * @return CryptoException
     */
    public static function decryptCannotCreateTempFile()
    {
        return self::decrypt("cannot create temp file on disk");
    }

    /**
     * @param string $path
     * @return CryptoException
     */
    public static function cannotReadFile(string $path)
    {
        return new self(sprintf("Error while reading keyfile %s: file is not readable by user (try chmod 644)", $path));
    }
}
