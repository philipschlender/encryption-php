<?php

namespace Tests;

use Encryption\Exceptions\EncryptionException;
use Encryption\Services\EncryptionServiceInterface;
use Encryption\Services\SymmetricEncryptionService;
use PHPUnit\Framework\Attributes\DataProvider;

class SymmetricEncryptionServiceTest extends TestCase
{
    protected EncryptionServiceInterface $encryptionService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->encryptionService = new SymmetricEncryptionService('1797980b15dd9e3240e8aee6d4ca548291618084b75cfe73ef9d040389ed4d1a');
    }

    public function testConstructInvalidKey(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('The key must be a hexadecimal string and must have a length of 64.');

        new SymmetricEncryptionService('');
    }

    #[DataProvider('dataProviderEncrypt')]
    public function testEncrypt(bool $binary): void
    {
        $expectedPlaintext = 'foobar';

        $ciphertext = $this->encryptionService->encrypt($expectedPlaintext, $binary);

        $plaintext = $this->encryptionService->decrypt($ciphertext, $binary);

        if ($binary) {
            $ciphertext = sodium_bin2hex($ciphertext);
        }

        $this->assertMatchesRegularExpression('/^[0-9a-f]{92}$/', $ciphertext);
        $this->assertEquals($expectedPlaintext, $plaintext);
    }

    /**
     * @return array<int,array<string,bool>>
     */
    public static function dataProviderEncrypt(): array
    {
        return [
            [
                'binary' => false,
            ],
            [
                'binary' => true,
            ],
        ];
    }

    #[DataProvider('dataProviderDecrypt')]
    public function testDecrypt(bool $binary): void
    {
        $ciphertext = '0328c4417419abdbd795e3bad68f84657e6ef4264d8982e664f31fa9bfc53cad6c50680f9cf7059550e7a3e8aaa9';

        $expectedPlaintext = 'foobar';

        if ($binary) {
            $ciphertext = sodium_hex2bin($ciphertext);
        }

        $plaintext = $this->encryptionService->decrypt($ciphertext, $binary);

        $this->assertEquals($expectedPlaintext, $plaintext);
    }

    /**
     * @return array<int,array<string,bool>>
     */
    public static function dataProviderDecrypt(): array
    {
        return [
            [
                'binary' => false,
            ],
            [
                'binary' => true,
            ],
        ];
    }

    public function testDecryptRandomKey(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to decrypt the ciphertext.');

        $encryptionService = new SymmetricEncryptionService($this->fakerService->getStringGenerator()->randomHexadecimal(64));

        $encryptionService->decrypt('0328c4417419abdbd795e3bad68f84657e6ef4264d8982e664f31fa9bfc53cad6c50680f9cf7059550e7a3e8aaa9');
    }

    public function testDecryptCiphertextTooShort(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('sodium_crypto_secretbox_open(): Argument #2 ($nonce) must be SODIUM_CRYPTO_SECRETBOX_NONCEBYTES bytes long');

        $this->encryptionService->decrypt('');
    }

    public function testDecryptRandomCiphertext(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to decrypt the ciphertext.');

        $this->encryptionService->decrypt($this->fakerService->getStringGenerator()->randomHexadecimal(92));
    }
}
