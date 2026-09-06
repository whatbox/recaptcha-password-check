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

    private function __construct(Prime $curve, BigInteger $privateKey)
    {
        $this->curve = $curve;
        $curve->rangeCheck($privateKey);
        $this->privateKey = $privateKey;
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

    /** @return array{PrimeInteger, PrimeInteger} */
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
            // BigInteger::toBytes() is minimal big-endian (no leading zeros)
            $candidate = $this->randomOracle($candidate->toBytes(), $prime);
        }
    }

    /** @return array{PrimeInteger, PrimeInteger} */
    private function decodePoint(string $ciphertext): array
    {
        return self::decodePointForCurve($ciphertext, $this->curve);
    }

    /** @param array{PrimeInteger, PrimeInteger} $point */
    private function encodePoint(array $point): string
    {
        [$x, $y] = $point;

        // Unlike BigInteger, PrimeField\Integer::toBytes() is zero-padded to the field length
        return ($y->isOdd() ? "\x03" : "\x02") . $x->toBytes();
    }

    /** @return array{PrimeInteger, PrimeInteger} */
    private static function decodePointForCurve(string $ciphertext, Prime $curve): array
    {
        // derivePoint() validates the prefix byte and that the point is on the curve, but not the length
        if (strlen($ciphertext) !== $curve->getLengthInBytes() + 1) {
            throw new InvalidArgumentException('Ciphertext has invalid length');
        }

        return $curve->derivePoint($ciphertext);
    }

    private function randomOracle(string $bytes, BigInteger $maxValue): BigInteger
    {
        $outputBitLength = $maxValue->getLength() + self::HASH_BITS;
        $iterations = intdiv($outputBitLength + self::HASH_BITS - 1, self::HASH_BITS);
        $excessBits = $iterations * self::HASH_BITS - $outputBitLength;

        $hashOutput = '';
        // Counter is a minimal big-endian integer; it never exceeds one byte for any supported curve
        for ($counter = 1; $counter <= $iterations; $counter++) {
            $hashOutput .= hash(self::HASH_ALGO, chr($counter) . $bytes, true);
        }

        return (new BigInteger($hashOutput, 256))->bitwise_rightShift($excessBits)->divide($maxValue)[1];
    }
}
