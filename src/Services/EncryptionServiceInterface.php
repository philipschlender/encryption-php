<?php

namespace Encryption\Services;

use Encryption\Exceptions\EncryptionException;

interface EncryptionServiceInterface
{
    /**
     * @throws EncryptionException
     */
    public function encrypt(#[\SensitiveParameter] string $plaintext, bool $binary = false): string;

    /**
     * @throws EncryptionException
     */
    public function decrypt(string $ciphertext, bool $binary = false): string;
}
