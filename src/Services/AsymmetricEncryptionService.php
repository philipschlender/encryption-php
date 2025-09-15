<?php

namespace Encryption\Services;

use Encryption\Exceptions\EncryptionException;

class AsymmetricEncryptionService implements EncryptionServiceInterface
{
    protected string $publicKey;

    protected ?string $privateKey;

    /**
     * @throws EncryptionException
     */
    public function __construct(
        #[\SensitiveParameter] string $publicKey,
        #[\SensitiveParameter] ?string $privateKey = null,
    ) {
        if (1 !== preg_match('/^[0-9a-f]{64}$/', $publicKey)) {
            throw new EncryptionException('The public key must be a hexadecimal string and must have a length of 64.');
        }

        if (is_string($privateKey) && 1 !== preg_match('/^[0-9a-f]{64}$/', $privateKey)) {
            throw new EncryptionException('The private key must be a hexadecimal string and must have a length of 64.');
        }

        try {
            $this->publicKey = sodium_hex2bin($publicKey);
            $this->privateKey = is_string($privateKey) ? sodium_hex2bin($privateKey) : null;
        } catch (\Throwable $throwable) {
            throw new EncryptionException($throwable->getMessage(), 0, $throwable);
        }
    }

    /**
     * @throws EncryptionException
     */
    public function encrypt(#[\SensitiveParameter] string $plaintext, bool $binary = false): string
    {
        try {
            $ciphertext = sodium_crypto_box_seal($plaintext, $this->publicKey);

            if (!$binary) {
                $ciphertext = sodium_bin2hex($ciphertext);
            }

            return $ciphertext;
        } catch (\Throwable $throwable) {
            throw new EncryptionException($throwable->getMessage(), 0, $throwable);
        }
    }

    /**
     * @throws EncryptionException
     */
    public function decrypt(string $ciphertext, bool $binary = false): string
    {
        try {
            if (!is_string($this->privateKey)) {
                throw new EncryptionException('The private key is required to decrypt the ciphertext.');
            }

            if (!$binary) {
                $ciphertext = sodium_hex2bin($ciphertext);
            }

            $key = sodium_crypto_box_keypair_from_secretkey_and_publickey($this->privateKey, $this->publicKey);

            $plaintext = sodium_crypto_box_seal_open($ciphertext, $key);

            if (!is_string($plaintext)) {
                throw new EncryptionException('Failed to decrypt the ciphertext.');
            }

            return $plaintext;
        } catch (\Throwable $throwable) {
            if ($throwable instanceof EncryptionException) {
                throw $throwable;
            }

            throw new EncryptionException($throwable->getMessage(), 0, $throwable);
        }
    }
}
