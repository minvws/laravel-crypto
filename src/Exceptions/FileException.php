<?php

namespace MinVWS\Crypto\Laravel\Exceptions;

use RuntimeException;

class FileException extends RuntimeException
{
    /**
     * @return FileException
     */
    public static function variableIsNotAResource(): FileException
    {
        return new self("variable is not a resource");
    }

    /**
     * @return FileException
     */
    public static function cannotCreateTempFile(): FileException
    {
        return new self("cannot create temp file on disk");
    }

    /**
     * @param string $path
     * @return FileException
     */
    public static function cannotReadFile(string $path): FileException
    {
        return new self(sprintf("Error while reading %s: file is not readable by user (try chmod 644)", $path));
    }

    /**
     * @return FileException
     */
    public static function cannotGetTempFilePath(): FileException
    {
        return new self("cannot get the temp file path");
    }
}
