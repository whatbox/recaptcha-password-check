<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Crypto;

use InvalidArgumentException;
use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;
use phpseclib3\Math\PrimeField\Integer as PrimeInteger;

final class EcCommutativeCipher
{
    private readonly Prime $curve;
    private readonly BigInteger $privateKey;
    private readonly HashType $hashType;
    private readonly int $fieldLength;

    private function __construct(Prime $curve, HashType $hashType, BigInteger $privateKey)
    {
        $this->curve = $curve;
        $this->hashType = $hashType;
        $curve->rangeCheck($privateKey);
        $this->privateKey = $privateKey;
        $this->fieldLength = $curve->getLengthInBytes();
    }

    public static function createWithNewKey(
        SupportedCurve $curve = SupportedCurve::SECP256R1,
        HashType $hashType = HashType::SHA256
    ): self {
        $curveImpl = $curve->curve();
        $privateKey = $curveImpl->createRandomMultiplier();

        return new self($curveImpl, $hashType, $privateKey);
    }

    public static function createFromKey(
        SupportedCurve $curve,
        string $keyBytes,
        HashType $hashType = HashType::SHA256
    ): self {
        $curveImpl = $curve->curve();
        $privateKey = self::bytesToBigInteger($keyBytes);

        return new self($curveImpl, $hashType, $privateKey);
    }

    public static function validateCiphertext(
        string $ciphertext,
        SupportedCurve $curve = SupportedCurve::SECP256R1
    ): bool {
        try {
            self::decodePointForCurve($ciphertext, $curve->curve());
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    public function getPrivateKeyBytes(): string
    {
        return self::bigIntegerToBytes($this->privateKey);
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
        $fieldLength = $curve->getLengthInBytes();
        if (strlen($ciphertext) !== $fieldLength + 1) {
            throw new InvalidArgumentException('Ciphertext has invalid length');
        }

        $prefix = ord($ciphertext[0]);
        if ($prefix !== 2 && $prefix !== 3) {
            throw new InvalidArgumentException('Unsupported point encoding');
        }

        $xBytes = substr($ciphertext, 1);
        $fieldX = $curve->convertInteger(self::bytesToBigInteger($xBytes));
        $rhs = $fieldX->multiply($fieldX)->multiply($fieldX)
            ->add($fieldX->multiply($curve->getA()))
            ->add($curve->getB());
        $sqrt = $rhs->squareRoot();
        if ($sqrt === false) {
            throw new InvalidArgumentException('Point not on curve');
        }

        $isOdd = $sqrt->isOdd();
        $shouldBeOdd = $prefix === 3;
        if ($isOdd !== $shouldBeOdd) {
            $sqrt = $sqrt->negate();
        }

        return [$fieldX, $sqrt];
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
        $hashBits = $this->hashType->bits();
        $outputBitLength = $maxValue->getLength() + $hashBits;
        $iterations = intdiv($outputBitLength + $hashBits - 1, $hashBits);
        $excessBits = $iterations * $hashBits - $outputBitLength;
        $hashOutput = new BigInteger(0);
        $counter = new BigInteger(1);

        for ($i = 0; $i < $iterations; $i++) {
            $hashOutput = $hashOutput->bitwise_leftShift($hashBits);
            $counterBytes = self::bigIntegerToBytes($counter);
            $hash = $this->hashType->digest($counterBytes . $bytes);
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
