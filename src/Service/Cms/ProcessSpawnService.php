<?php

namespace MinVWS\Crypto\Laravel\Service\Cms;

use MinVWS\Crypto\Laravel\CmsCryptoInterface;
use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use MinVWS\Crypto\Laravel\Service\TempFileService;
use MinVWS\Crypto\Laravel\TempFileInterface;
use Symfony\Component\Process\Process;

class ProcessSpawnService implements CmsCryptoInterface
{
    /**
     * @var string[] Paths to certificates that are used to encrypt the data. The privkey of any of these certs can
     * decrypt the data. Useful when you want to decrypt the same data at multiple places. */
    protected array $encryptionCertsPath;

    /**
     * @var string|null Path to single certificate used for decrypting the data. The data could be encrypted for
     * multiple certs, but this software only will use this cert to (try to) decode.
     */
    protected ?string $decryptionCertPath;

    /** @var string|null The path to the private key of $decryptionCert cert. Needed to decrypt the actual data. */
    protected ?string $decryptionCertKeyPath;

    public function __construct(
        array $encryptionCertsPath = [],
        ?string $decryptionCertPath = null,
        ?string $decryptionCertKeyPath = null,
    ) {
        $this->encryptionCertsPath = $encryptionCertsPath;
        $this->decryptionCertPath = $decryptionCertPath;
        $this->decryptionCertKeyPath = $decryptionCertKeyPath;
    }


    /**
     * @param string $plainText
     * @return string
     */
    public function encrypt(string $plainText): string
    {
        if (count($this->encryptionCertsPath) == 0) {
            throw CryptoException::encrypt('cannot encrypt without providing at least one certificate');
        }

        $args = array_merge(
            ['openssl', 'cms', '-stream', '-encrypt', '-aes-256-cbc', '-outform', 'PEM'],
            $this->encryptionCertsPath
        );
        $process = new Process($args);
        $process->setInput($plainText);
        $process->run();

        $errOutput = $process->getErrorOutput();
        if (!empty($errOutput)) {
            if ($process->getExitCode() == 1 && $this->isLibreSSL()) {
                throw CryptoException::opensslVersion();
            }
            if ($process->getExitCode() == 127) {
                throw CryptoException::opensslNotFound();
            }
            throw CryptoException::encrypt($errOutput);
        }

        return $process->getOutput();
    }

    /**
     * @param string $cipherText
     * @return string
     */
    public function decrypt(string $cipherText): string
    {
        if ($this->decryptionCertPath === null || $this->decryptionCertKeyPath === null) {
            throw CryptoException::decrypt("no decryption certificate or key provided");
        }

        if (!is_readable($this->decryptionCertPath)) {
            throw CryptoException::cannotReadFile($this->decryptionCertPath);
        }
        if (!is_readable($this->decryptionCertKeyPath)) {
            throw CryptoException::cannotReadFile($this->decryptionCertKeyPath);
        }

        $args = [
            'openssl', 'cms', '-decrypt', '-inform', 'PEM', 
            '-inkey', $this->decryptionCertKeyPath,
            '-recip', $this->decryptionCertPath
        ];
        $process = new Process($args);
        $process->setInput($cipherText);
        $process->run();

        $errOutput = $process->getErrorOutput();
        if (!empty($errOutput)) {
            if ($process->getExitCode() == 1 && $this->isLibreSSL()) {
                throw CryptoException::opensslVersion();
            }
            if ($process->getExitCode() == 127) {
                throw CryptoException::opensslNotFound();
            }

            throw CryptoException::decrypt($errOutput);
        }

        return $process->getOutput();
    }

    protected function isLibreSSL(): bool
    {
        $process = new Process(['openssl', 'version']);
        $process->run();
        if ($process->getExitCode() != 0) {
            return false;    // assume ok
        }

        $processOutput = $process->getOutput();
        return strpos($processOutput, 'LibreSSL') !== false;
    }
}
