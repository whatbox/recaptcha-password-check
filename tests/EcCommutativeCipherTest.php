<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Tests;

use PHPUnit\Framework\TestCase;
use ReCaptcha\PasswordCheck\Crypto\EcCommutativeCipher;

class EcCommutativeCipherTest extends TestCase
{
    public function testEncryptDecryptRoundTrip(): void
    {
        $cipher = EcCommutativeCipher::createWithNewKey();
        $plaintext = random_bytes(32);

        $encrypted = $cipher->encrypt($plaintext);
        $decrypted = $cipher->decrypt($encrypted);

        $this->assertSame($cipher->hashIntoCurve($plaintext), $decrypted);
    }

    public function testCommutativity(): void
    {
        $cipherA = EcCommutativeCipher::createWithNewKey();
        $cipherB = EcCommutativeCipher::createWithNewKey();
        $plaintext = random_bytes(32);

        $encryptedByA = $cipherA->encrypt($plaintext);
        $reencryptedByB = $cipherB->reEncrypt($encryptedByA);

        $encryptedByB = $cipherB->encrypt($plaintext);
        $reencryptedByA = $cipherA->reEncrypt($encryptedByB);

        $this->assertSame($reencryptedByB, $reencryptedByA);
    }

    public function testValidateCiphertext(): void
    {
        $cipher = EcCommutativeCipher::createWithNewKey();
        $ciphertext = $cipher->encrypt(random_bytes(32));

        $this->assertTrue(EcCommutativeCipher::validateCiphertext($ciphertext));
        $this->assertFalse(EcCommutativeCipher::validateCiphertext(random_bytes(strlen($ciphertext))));
    }
}
