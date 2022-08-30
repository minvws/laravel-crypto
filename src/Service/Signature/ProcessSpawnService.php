<?php

namespace MinVWS\Crypto\Laravel\Service\Signature;

use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\Exceptions\FileException;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use MinVWS\Crypto\Laravel\SignatureSignCryptoInterface;
use MinVWS\Crypto\Laravel\SignatureVerifyCryptoInterface;
use MinVWS\Crypto\Laravel\Traits\TempFiles;
use Symfony\Component\Process\Process;

class ProcessSpawnService implements SignatureCryptoInterface, SignatureSignCryptoInterface, SignatureVerifyCryptoInterface
{
    use TempFiles;

    /** @var ?string */
    protected $certPath;
    /** @var ?string */
    protected $privKeyPath;
    /** @var ?string */
    protected $privKeyPass;
    /** @var ?string */
    protected $certChainPath;

    /**
     * ProcessSpawnService constructor.
     *
     * @param string|null $certPath
     * @param string|null $privKeyPath
     * @param string|null $privKeyPass
     * @param string|null $certChainPath
     */
    public function __construct(?string $certPath = null, ?string $privKeyPath = null, ?string $privKeyPass = null, ?string $certChainPath = null)
    {
        $this->certPath = $certPath;
        $this->privKeyPath = $privKeyPath;
        $this->privKeyPass = $privKeyPass;
        $this->certChainPath = $certChainPath;
    }

    /**
     * @param string $payload
     * @param bool $detached
     * @return string
     */
    public function sign(string $payload, bool $detached = false): string
    {
        if (!is_readable($this->privKeyPath)) {
            throw FileException::cannotReadFile($this->privKeyPath);
        }

        $args = [
            'openssl', 'cms', '-sign', '-signer', $this->certPath, '-inkey', $this->privKeyPath, '-outform', 'DER'
        ];
        if (!$detached) {
            $args = array_merge($args, ['-nodetach']);
        }
        if (!empty($this->privKeyPass)) {
            $args = array_merge($args, ['-passin', $this->privKeyPass]);
        }
        if (!empty($this->certChainPath)) {
            $args = array_merge($args, ['-CAfile', $this->certChainPath]);
        }

        $process = new Process($args);
        $process->setInput($payload);
        $process->run();

        $errOutput = $process->getErrorOutput();
        if (!empty($errOutput)) {
            throw CryptoException::sign($errOutput);
        }

        return base64_encode($process->getOutput());
    }

    /**
     * @param string $signedPayload
     * @param string|null $content
     * @param string|null $certificate
     * @param SignatureVerifyConfig|null $verifyConfig
     * @return bool
     */
    public function verify(string $signedPayload, string $content = null, string $certificate = null, ?SignatureVerifyConfig $verifyConfig = null): bool
    {
        $tmpFile = null;
        $certTmpFile = null;

        try {
            $args = ['openssl', 'cms', '-verify', '-inform', 'DER', '-noout', '-purpose', 'any', ...$this->getOpenSslTags($verifyConfig)];
            if (!empty($this->certChainPath)) {
                $args = array_merge($args, ['-CAfile', $this->certChainPath]);
            }

            if ($content !== null) {
                $tmpFile = $this->createTempFileWithContent($content);
                $args = array_merge($args, ['-content', $this->getTempFilePath($tmpFile)]);
            }

            if ($certificate !== null) {
                $certTmpFile = $this->createTempFileWithContent($certificate);
                $args = array_merge($args, ['-certfile', $this->getTempFilePath($certTmpFile), '-nointern']);
            }

            $process = new Process($args);
            $process->setInput(base64_decode($signedPayload));
            $process->run();

            $errOutput = $process->getErrorOutput();

            // Successful and failure are expected.
            if (
                !empty($errOutput)
                && !str_starts_with($errOutput, "Verification successful")
                && !str_starts_with($errOutput, "Verification failure")
            ) {
                throw CryptoException::verify($errOutput);
            }

            return $process->getExitCode() === 0;
        } finally {
            $this->closeTempFile($tmpFile);
            $this->closeTempFile($certTmpFile);
        }
    }



    protected function getOpenSslTags(?SignatureVerifyConfig $config): array
    {
        $flags = [];
        if ($config?->getBinary()) {
            $flags[] = '-binary';
        }

        return $flags;
    }
}
