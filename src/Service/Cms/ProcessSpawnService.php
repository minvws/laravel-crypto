<?php

namespace MinVWS\Crypto\Laravel\Service\Cms;

use MinVWS\Crypto\Laravel\CmsCryptoInterface;
use MinVWS\Crypto\Laravel\Exceptions\CryptoException;
use Symfony\Component\Process\Process;

class ProcessSpawnService implements CmsCryptoInterface
{
    /**
     * @var string[] Paths to certificates that are used to encrypt the data. The privkey of any of these certs can
     * decrypt the data. Useful when you want to decrypt the same data at multiple places. */
    protected $encryptionCertsPath;

    /**
     * @var string Path to single certificate used for decrypting the data. The data could be encrypted for multiple
     * certs, but this software only will use this cert to (try to) decode.
     */
    protected $decryptionCertPath;

    /** @var string The path to the private key of $decryptionCert cert. Needed to decrypt the actual data. */
    protected $decryptionCertKeyPath;

    /**
     * @param array $encryptionCertsPath
     * @param string $decryptionCertPath
     * @param string $decryptionCertKeyPath
     */
    public function __construct(array $encryptionCertsPath, string $decryptionCertPath, string $decryptionCertKeyPath)
    {
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
        $args = array_merge(
            ['openssl', 'cms', '-stream', '-encrypt', '-aes-256-cbc', '-outform', 'PEM'],
            $this->encryptionCertsPath
        );
        $process = new Process($args);
        $process->setInput($plainText);
        $process->run();

        $errOutput = $process->getErrorOutput();
        if (!empty($errOutput)) {
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
        if (!is_readable($this->decryptionCertKeyPath)) {
            throw CryptoException::cannotReadFile($this->decryptionCertKeyPath);
        }

        $args = [
            'openssl', 'cms', '-decrypt', '-inform', 'PEM', '-inkey',
            $this->decryptionCertKeyPath, $this->decryptionCertPath
        ];
        $process = new Process($args);
        $process->setInput($cipherText);
        $process->run();

        $errOutput = $process->getErrorOutput();
        if (!empty($errOutput)) {
            throw CryptoException::decrypt($errOutput);
        }

        return $process->getOutput();
    }
}
