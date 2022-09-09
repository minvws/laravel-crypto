<?php

namespace MinVWS\Crypto\Laravel\Service;

use MinVWS\Crypto\Laravel\Exceptions\FileException;
use MinVWS\Crypto\Laravel\TempFileInterface;

class TempFileService implements TempFileInterface
{
    /**
     * Creates a temp file with the supplied content and return the path of the file.
     * @param string $content
     * @return resource
     */
    public function createTempFileWithContent(string $content)
    {
        $tmpFile = $this->createTempFile();
        fwrite($tmpFile, $content);

        return $tmpFile;
    }

    /**
     * Get the file path of the resource.
     * @param ?resource $resource
     * @return string
     */
    public function getTempFilePath($resource): string
    {
        if (!is_resource($resource)) {
            throw FileException::variableIsNotAResource();
        }

        return stream_get_meta_data($resource)['uri'];
    }

    /**
     * Creates a temp file
     * @return resource
     */
    public function createTempFile()
    {
        $tmpFile = tmpfile();
        if (!is_resource($tmpFile)) {
            throw FileException::cannotCreateTempFile();
        }

        return $tmpFile;
    }

    /**
     * @param ?resource $tmpFile
     * @return void
     */
    public function closeTempFile($tmpFile): void
    {
        if (!is_resource($tmpFile)) {
            return;
        }
        fclose($tmpFile);
    }
}
