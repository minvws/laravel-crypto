<?php

namespace MinVWS\Crypto\Laravel\Service\Signature;

use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use MinVWS\Crypto\Laravel\TempFileInterface;
use Symfony\Component\Process\Process;

class ProcessSpawnService implements SignatureCryptoInterface
{
    protected string $certPath;
    protected string $privKeyPath;
    protected string $privKeyPass;
    protected string $certChainPath;
    protected TempFileInterface $tempFileService;

    /**
     * ProcessSpawnService constructor.
     *
     * @param string|null $certPath
     * @param string|null $privKeyPath
     * @param string|null $privKeyPass
     * @param string|null $certChainPath
     * @param TempFileInterface|null $tempFileService
     */
    public function __construct(
        ?string $certPath = null,
        ?string $privKeyPath = null,
        ?string $privKeyPass = null,
        ?string $certChainPath = null,
        ?TempFileInterface $tempFileService = null,
    ) {
        $this->certPath = $certPath ?? '';
        $this->privKeyPath = $privKeyPath ?? '';
        $this->privKeyPass = $privKeyPass ?? '';
        $this->certChainPath = $certChainPath ?? '';
        $this->tempFileService = $tempFileService ?? app(TempFileInterface::class);
    }

    /**
     * @param string $payload
     * @param bool $detached
     * @return string
     */
    public function sign(string $payload, bool $detached = false): string
    {
        if (!is_readable($this->certPath)) {
            throw CryptoException::cannotReadFile($this->certPath);
        }
        if (!is_readable($this->privKeyPath)) {
            throw CryptoException::cannotReadFile($this->privKeyPath);
        }
        if (!empty($this->certChainPath) && !is_readable($this->certChainPath)) {
            throw CryptoException::cannotReadFile($this->certChainPath);
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
    public function verify(
        string $signedPayload,
        string $content = null,
        string $certificate = null,
        ?SignatureVerifyConfig $verifyConfig = null
    ): bool {
        $tmpFile = null;
        $certTmpFile = null;

        try {
            $args = array_merge([
                'openssl', 'cms', '-verify',
                '-inform', 'DER',
                '-noout',
            ], $this->getOpenSslTags($verifyConfig));

            if (!empty($this->certChainPath)) {
                $args = array_merge($args, ['-CAfile', $this->certChainPath]);
            }

            if ($content !== null) {
                $tmpFile = $this->tempFileService->createTempFileWithContent($content);
                $args = array_merge($args, ['-content', $this->tempFileService->getTempFilePath($tmpFile)]);
            }

            if ($certificate !== null) {
                $certTmpFile = $this->tempFileService->createTempFileWithContent($certificate);
                $args = array_merge(
                    $args,
                    [
                        '-certfile',
                        $this->tempFileService->getTempFilePath($certTmpFile),
                        '-nointern',
                    ],
                );
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
            $this->tempFileService->closeTempFile($tmpFile);
            $this->tempFileService->closeTempFile($certTmpFile);
        }
    }

    protected function getOpenSslTags(?SignatureVerifyConfig $config): array
    {
        $flags = [];
        if ($config?->getBinary()) {
            $flags[] = '-binary';
        }
        if ($config?->getNoVerify()) {
            // When we supply a cert chain, then we want to check the ca certificate
            // Else we want to ignore the certificate purpose
            if (!$this->certChainPath) {
                $flags[] = '-noverify';
            }

            $flags[] = '-purpose';
            $flags[] = 'any';
        }

        return $flags;
    }
}
