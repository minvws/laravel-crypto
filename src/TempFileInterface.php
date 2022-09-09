<?php

namespace MinVWS\Crypto\Laravel;

interface TempFileInterface
{
    /**
     * Creates a temp file with the supplied content and return the path of the file.
     * @param string $content
     * @return resource
     */
    public function createTempFileWithContent(string $content);

    /**
     * Get the file path of the resource.
     * @param ?resource $resource
     * @return string
     */
    public function getTempFilePath($resource): string;

    /**
     * Creates a temp file
     * @return resource
     */
    public function createTempFile();

    /**
     * @param ?resource $tmpFile
     * @return void
     */
    public function closeTempFile($tmpFile): void;
}
