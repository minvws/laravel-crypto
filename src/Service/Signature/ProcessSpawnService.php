<?php

namespace MinVWS\Crypto\Laravel\Service\Signature;

use MinVWS\Crypto\Laravel\CryptoException;
use MinVWS\Crypto\Laravel\SignatureCryptoInterface;
use Symfony\Component\Process\Process;

class ProcessSpawnService implements SignatureCryptoInterface
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
     * ProcessSpawnService constructor.
     *
     * @param string $certPath
     * @param string $privKeyPath
     * @param string $privKeyPass
     * @param string $certChainPath
     */
    public function __construct(string $certPath, string $privKeyPath, string $privKeyPass, string $certChainPath)
    {
        $this->certPath = $certPath;
        $this->privKeyPath = $privKeyPath;
        $this->privKeyPass = $privKeyPass;
        $this->certChainPath = $certChainPath;

        if (!is_readable($privKeyPath)) {
            throw CryptoException::cannotReadFile($privKeyPass);
        }
    }

    /**
     * @param string $payload
     * @param bool $detached
     * @return string
     */
    public function sign(string $payload, bool $detached = false): string
    {
        $args = [
            'openssl', 'cms', '-sign', '-signer', $this->certPath, '-inkey', $this->privKeyPath, '-outform', 'DER'
        ];
        if (!$detached) {
            $args = array_merge($args, ['-nodetach']);
        }
        if ($this->privKeyPass != "") {
            $args = array_merge($args, ['-passin', $this->privKeyPass]);
        }
        if ($this->certChainPath != "") {
            $args = array_merge($args, ['-CAfile', $this->certChainPath]);
        }

        $process = new Process($args);
        $process->setInput($payload);
        $process->run();

        $errOutput = $process->getErrorOutput();
        if ($errOutput != "") {
            print $errOutput;
//            Log::error($errOutput);
        }

        return base64_encode($process->getOutput());
    }

    /**
     * @param string $signedPayload
     * @param string|null $content
     * @return bool
     */
    public function verify(string $signedPayload, string $content = null): bool
    {
        $tmpFile = null;

        try {
            $args = ['openssl', 'cms', '-verify', '-inform', 'DER', '-noout', '-purpose', 'any'];
            if ($this->certChainPath != "") {
                $args = array_merge($args, ['-CAfile', $this->certChainPath]);
            }


            if ($content !== null) {
                // @TODO: generate tmp file with data
                $tmpFile = tmpfile();
                if (!is_resource($tmpFile)) {
                    throw CryptoException::verify("cannot create temp file on disk");
                }
                $tmpFilePath = stream_get_meta_data($tmpFile)['uri'];
                file_put_contents($tmpFilePath, $content);
                $args = array_merge($args, ['-content', $tmpFilePath]);
            }

            $process = new Process($args);
            $process->setInput(base64_decode($signedPayload));
            $process->run();

            $errOutput = $process->getErrorOutput();
            if ($errOutput != "") {
                Log::error($errOutput);
            }

            return $process->getExitCode() == 0;
        } finally {
            if ($tmpFile) {
                fclose($tmpFile);
            }
        }
    }
}
