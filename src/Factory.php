<?php

namespace MinVWS\Crypto\Laravel;

use MinVWS\Crypto\Laravel\Service\Cms;
use MinVWS\Crypto\Laravel\Service\Signature;
use MinVWS\Crypto\Laravel\Service\Sealbox\SealboxService;
use MinVWS\Crypto\Laravel\Service\TempFileService;

class Factory
{
    public static function createCmsCryptoService(
        array $encryptionCertPaths = [],
        ?string $decryptionCertPath = null,
        ?string $decryptionKeyPath = null,
        bool $forceProcessSpawn = false
    ): CmsCryptoInterface {
        if (function_exists('openssl_cms_encrypt') && !$forceProcessSpawn) {
            $tmpFile = new TempFileService();

            return new Cms\NativeService(
                $encryptionCertPaths,
                $decryptionCertPath,
                $decryptionKeyPath,
                $tmpFile
            );
        }

        return new Cms\ProcessSpawnService(
            $encryptionCertPaths,
            $decryptionCertPath,
            $decryptionKeyPath,
        );
    }

    public static function createSealboxCryptoService(
        ?string $privKey = null,
        ?string $recipientPubKey = null
    ): SealboxCryptoInterface {
        return new SealboxService($privKey, $recipientPubKey);
    }

    public static function createSignatureCryptoService(
        ?string $certificatePath = null,
        ?string $certificateKeyPath = null,
        ?string $certificateKeyPass = null,
        ?string $certificateChain = null,
        bool $forceProcessSpawn = false
    ): SignatureCryptoInterface {
        $args = [
            $certificatePath,
            $certificateKeyPath,
            $certificateKeyPass,
            $certificateChain,
            app(TempFileInterface::class),
        ];

        if (function_exists('openssl_cms_sign') && !$forceProcessSpawn) {
            return new Signature\NativeService(...$args);
        }

        return new Signature\ProcessSpawnService(...$args);
    }
}
