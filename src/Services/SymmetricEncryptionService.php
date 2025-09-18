<?php

namespace Encryption\Services;

use Encryption\Exceptions\EncryptionException;

class SymmetricEncryptionService implements EncryptionServiceInterface
{
    protected string $key;

    /**
     * @throws EncryptionException
     */
    public function __construct(
        #[\SensitiveParameter] string $key,
    ) {
        if (1 !== preg_match('/^[0-9a-f]{64}$/', $key)) {
            throw new EncryptionException('The key must be a hexadecimal string and must have a length of 64.');
        }

        try {
            $this->key = sodium_hex2bin($key);
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
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

            $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $this->key);

            $ciphertext = sprintf('%s%s', $nonce, $ciphertext);

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
            if (!$binary) {
                $ciphertext = sodium_hex2bin($ciphertext);
            }

            $nonce = substr($ciphertext, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

            $ciphertext = substr($ciphertext, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

            $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $this->key);

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
