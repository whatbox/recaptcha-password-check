<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Crypto;

use InvalidArgumentException;
use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Crypt\EC\Curves\secp256r1;
use phpseclib3\Math\BigInteger;
use phpseclib3\Math\PrimeField\Integer as PrimeInteger;

final class EcCommutativeCipher
{
    private const HASH_ALGO = 'sha256';
    private const HASH_BITS = 256;

    private readonly Prime $curve;
    private readonly BigInteger $privateKey;
    private readonly int $fieldLength;

    private function __construct(Prime $curve, BigInteger $privateKey)
    {
        $this->curve = $curve;
        $curve->rangeCheck($privateKey);
        $this->privateKey = $privateKey;
        $this->fieldLength = $curve->getLengthInBytes();
    }

    public static function createWithNewKey(): self
    {
        $curve = new secp256r1();
        $privateKey = $curve->createRandomMultiplier();

        return new self($curve, $privateKey);
    }

    public static function validateCiphertext(string $ciphertext): bool
    {
        try {
            self::decodePointForCurve($ciphertext, new secp256r1());
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    public function encrypt(string $plaintext): string
    {
        $point = $this->hashIntoCurvePoint($plaintext);
        $encrypted = $this->curve->multiplyPoint($point, $this->privateKey);

        return $this->encodePoint($encrypted);
    }

    public function reEncrypt(string $ciphertext): string
    {
        $point = $this->decodePoint($ciphertext);
        $reencrypted = $this->curve->multiplyPoint($point, $this->privateKey);

        return $this->encodePoint($reencrypted);
    }

    public function decrypt(string $ciphertext): string
    {
        $point = $this->decodePoint($ciphertext);
        $order = $this->curve->getOrder();
        $inverse = $this->privateKey->modInverse($order);
        $decrypted = $this->curve->multiplyPoint($point, $inverse);

        return $this->encodePoint($decrypted);
    }

    public function hashIntoCurve(string $input): string
    {
        return $this->encodePoint($this->hashIntoCurvePoint($input));
    }

    private function hashIntoCurvePoint(string $input): array
    {
        $prime = $this->curve->getModulo();
        $candidate = $this->randomOracle($input, $prime);
        while (true) {
            $fieldX = $this->curve->convertInteger($candidate);
            $rhs = $fieldX->multiply($fieldX)->multiply($fieldX)
                ->add($fieldX->multiply($this->curve->getA()))
                ->add($this->curve->getB());
            /** @var PrimeInteger|false $sqrt */
            $sqrt = $rhs->squareRoot();
            if ($sqrt !== false) {
                if ($sqrt->isOdd()) {
                    $sqrt = $sqrt->negate();
                }
                return [$fieldX, $sqrt];
            }
            $candidate = $this->randomOracle(self::bigIntegerToBytes($candidate), $prime);
        }
    }

    private function decodePoint(string $ciphertext): array
    {
        return self::decodePointForCurve($ciphertext, $this->curve);
    }

    private function encodePoint(array $point): string
    {
        [$x, $y] = $point;
        $xBytes = $this->padToFieldLength(self::bigIntegerToBytes($x->toBigInteger()));
        $prefix = $y->isOdd() ? "\x03" : "\x02";

        return $prefix . $xBytes;
    }

    private static function decodePointForCurve(string $ciphertext, Prime $curve): array
    {
        // derivePoint() validates the prefix byte and that the point is on the curve, but not the length
        if (strlen($ciphertext) !== $curve->getLengthInBytes() + 1) {
            throw new InvalidArgumentException('Ciphertext has invalid length');
        }

        return $curve->derivePoint($ciphertext);
    }

    private function padToFieldLength(string $bytes): string
    {
        $trimmed = ltrim($bytes, "\0");
        if ($trimmed === '') {
            $trimmed = "\0";
        }

        return str_pad($trimmed, $this->fieldLength, "\0", STR_PAD_LEFT);
    }

    private function randomOracle(string $bytes, BigInteger $maxValue): BigInteger
    {
        $outputBitLength = $maxValue->getLength() + self::HASH_BITS;
        $iterations = intdiv($outputBitLength + self::HASH_BITS - 1, self::HASH_BITS);
        $excessBits = $iterations * self::HASH_BITS - $outputBitLength;
        $hashOutput = new BigInteger(0);
        $counter = new BigInteger(1);

        for ($i = 0; $i < $iterations; $i++) {
            $hashOutput = $hashOutput->bitwise_leftShift(self::HASH_BITS);
            $counterBytes = self::bigIntegerToBytes($counter);
            $hash = hash(self::HASH_ALGO, $counterBytes . $bytes, true);
            $hashOutput = $hashOutput->add(self::bytesToBigInteger($hash));
            $counter = $counter->add(new BigInteger(1));
        }

        $hashOutput = $hashOutput->bitwise_rightShift($excessBits);

        return $hashOutput->divide($maxValue)[1];
    }

    private static function bigIntegerToBytes(BigInteger $value): string
    {
        $bytes = $value->toBytes();
        return $bytes === '' ? "\0" : ltrim($bytes, "\0");
    }

    private static function bytesToBigInteger(string $bytes): BigInteger
    {
        return new BigInteger("\0" . $bytes, 256);
    }
}
