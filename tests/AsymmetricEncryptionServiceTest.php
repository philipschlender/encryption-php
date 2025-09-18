<?php

namespace Tests;

use Encryption\Exceptions\EncryptionException;
use Encryption\Services\AsymmetricEncryptionService;
use Encryption\Services\EncryptionServiceInterface;
use PHPUnit\Framework\Attributes\DataProvider;

class AsymmetricEncryptionServiceTest extends TestCase
{
    protected EncryptionServiceInterface $encryptionService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->encryptionService = new AsymmetricEncryptionService('19389b3340a3915d6bf9f438874dc2347c9627537042f3cff28dee4a1f2b9e5a', 'e80a7f7c9653a140c898b2d30680c3937c4a68ab030e6d6a94f3142168c1a781');
    }

    public function testConstructInvalidPublicKey(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('The public key must be a hexadecimal string and must have a length of 64.');

        new AsymmetricEncryptionService('', 'e80a7f7c9653a140c898b2d30680c3937c4a68ab030e6d6a94f3142168c1a781');
    }

    public function testConstructInvalidPrivateKey(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('The private key must be a hexadecimal string and must have a length of 64.');

        new AsymmetricEncryptionService('19389b3340a3915d6bf9f438874dc2347c9627537042f3cff28dee4a1f2b9e5a', '');
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

        $this->assertMatchesRegularExpression('/^[0-9a-f]{108}$/', $ciphertext);
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
        $ciphertext = '476aaa8139726f7ff04d2ec057323b893c2949a0ba355410f6166b115176e067434cd3ab4675114a01eb08fdd80d495d0549b09c7628';

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

    public function testDecryptNoPrivateKey(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('The private key is required to decrypt the ciphertext.');

        $encryptionService = new AsymmetricEncryptionService('19389b3340a3915d6bf9f438874dc2347c9627537042f3cff28dee4a1f2b9e5a', null);

        $encryptionService->decrypt('476aaa8139726f7ff04d2ec057323b893c2949a0ba355410f6166b115176e067434cd3ab4675114a01eb08fdd80d495d0549b09c7628');
    }

    public function testDecryptRandomPublicAndPrivateKey(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to decrypt the ciphertext.');

        $encryptionService = new AsymmetricEncryptionService($this->fakerService->getStringGenerator()->randomHexadecimal(64), $this->fakerService->getStringGenerator()->randomHexadecimal(64));

        $encryptionService->decrypt('476aaa8139726f7ff04d2ec057323b893c2949a0ba355410f6166b115176e067434cd3ab4675114a01eb08fdd80d495d0549b09c7628');
    }

    public function testDecryptCiphertextTooShort(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to decrypt the ciphertext.');

        $this->encryptionService->decrypt('');
    }

    public function testDecryptRandomCiphertext(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to decrypt the ciphertext.');

        $this->encryptionService->decrypt($this->fakerService->getStringGenerator()->randomHexadecimal(108));
    }
}
