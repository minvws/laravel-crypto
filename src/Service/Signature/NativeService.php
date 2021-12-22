<?php

namespace MinVWS\Crypto\Laravel\Service\Signature;

use Illuminate\Support\Facades\Log;
use MinVWS\Crypto\Laravel\CryptoException;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use Symfony\Component\Process\Process;

class NativeService implements SignatureCryptoInterface
{
    /** @var string */
    protected $certPath;
    /** @var string */
    protected $privKeyPath;
    /** @var string */
    protected $privKeyPass;
    /** @var string */
    protected $certChainPath;

    /**
     * NativeService constructor.
     *
     * @param string $certPath
     * @param string $privKeyPath
     * @param string $privKeyPass
     * @param string $certChainPath
     */
    public function __construct(string $certPath, string $privKeyPath, string $privKeyPass, string $certChainPath)
    {
        $this->certPath = "file://" . $certPath;
        $this->privKeyPath = "file://" . $privKeyPath;
        $this->privKeyPass = $privKeyPass;
        $this->certChainPath = $certChainPath;

        if (!is_readable($privKeyPath)) {
            throw CryptoException::cannotReadFile($privKeyPath);
        }
    }

    /**
     * @param string $payload
     * @param bool $detached
     * @return string
     */
    public function sign(string $payload, bool $detached = false): string
    {
        $tmpFileSignature = null;
        $tmpFileData = null;

        try {
            $tmpFileData = tmpfile();
            if (!is_resource($tmpFileData)) {
                throw CryptoException::sign("cannot create temp file on disk");
            }
            $tmpFileDataPath = stream_get_meta_data($tmpFileData)['uri'];
            file_put_contents($tmpFileDataPath, $payload);

            $tmpFileSignature = tmpfile();
            if (!is_resource($tmpFileSignature)) {
                throw CryptoException::sign("cannot create temp file on disk");
            }
            $tmpFileSignaturePath = stream_get_meta_data($tmpFileSignature)['uri'];

            $headers = array();

            $flags = 0;
            if ($detached) {
                $flags |= OPENSSL_CMS_DETACHED;
            }

            // Sign it
            openssl_cms_sign(
                $tmpFileDataPath,
                $tmpFileSignaturePath,
                $this->certPath,
                array($this->privKeyPath, $this->privKeyPass),
                $headers,
                $flags,
                OPENSSL_ENCODING_DER,
                $this->certChainPath
            );

            // Grab signature contents
            $signature = file_get_contents($tmpFileSignaturePath);
            if ($signature === false) {
                throw CryptoException::sign("could not read signature from disk");
            }

            return base64_encode($signature);
        } finally {
            // Close/remove temp files, even when errored
            if (is_resource($tmpFileData)) {
                fclose($tmpFileData);
            }
            if (is_resource($tmpFileSignature)) {
                fclose($tmpFileSignature);
            }
        }
    }

    /**
     * @param string $signedPayload
     * @param string|null $content
     * @return bool
     */
    public function verify(string $signedPayload, string $content = null): bool
    {
        $tmpFileContentData = null;
        $tmpFileContentDataPath = null;
        $tmpFileSignedData = null;
        $tmpFileSignedDataPath = null;

        try {
            $detached = !is_null($content);

            $tmpFileSignedData = tmpfile();
            if (!is_resource($tmpFileSignedData)) {
                throw CryptoException::verify("cannot create temp file on disk");
            }
            $tmpFileSignedDataPath = stream_get_meta_data($tmpFileSignedData)['uri'];
            file_put_contents($tmpFileSignedDataPath, base64_decode($signedPayload));

            $flags = OPENSSL_CMS_NOVERIFY;
            if ($detached) {
                $flags |= OPENSSL_CMS_DETACHED;

                /** @var resource $tmpFileSignedData */
                $tmpFileContentData = tmpfile();
                if (!is_resource($tmpFileContentData)) {
                    throw CryptoException::verify("cannot create temp file on disk");
                }
                $tmpFileContentDataPath = stream_get_meta_data($tmpFileContentData)['uri'];
                file_put_contents($tmpFileContentDataPath, $content);
            }

            /*
               NOTE: Detached verification is special, it means the content and signature arguments
               must be switched around.
            */

            // Verify it
            $res = openssl_cms_verify(
                ($detached ? $tmpFileContentDataPath : $tmpFileSignedDataPath) ?? '',
                $flags,
                null,
                array(),
                null,
                null,
                null,
                $detached ? $tmpFileSignedDataPath : $tmpFileContentDataPath,
                OPENSSL_ENCODING_DER,
            );

            return $res;
        } finally {
            // Close/remove temp files, even when errored
            if (is_resource($tmpFileSignedData)) {
                fclose($tmpFileSignedData);
            }
            if (is_resource($tmpFileContentData)) {
                fclose($tmpFileContentData);
            }
        }
    }
}
