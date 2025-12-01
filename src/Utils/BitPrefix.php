<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Utils;

final class BitPrefix
{
    private const BYTE_SIZE = 8;

    private function __construct(
        private readonly string $prefix,
        private readonly int $length
    ) {
    }

    public static function fromBytes(string $bytes, int $prefixLength): self
    {
        $totalBits = strlen($bytes) * self::BYTE_SIZE;
        if ($prefixLength < 0 || $prefixLength > $totalBits) {
            throw new \InvalidArgumentException('Invalid prefix length for provided bytes');
        }

        if ($prefixLength === 0) {
            return new self('', 0);
        }

        $byteLength = intdiv($prefixLength + self::BYTE_SIZE - 1, self::BYTE_SIZE);
        $prefix = substr($bytes, 0, $byteLength);
        $mask = self::bitMask($prefixLength);
        $lastIndex = $byteLength - 1;
        $prefix[$lastIndex] = chr(ord($prefix[$lastIndex]) & $mask);

        return new self($prefix, $prefixLength);
    }

    public function getPrefix(): string
    {
        return $this->prefix;
    }

    public function getLength(): int
    {
        return $this->length;
    }

    private static function bitMask(int $prefixLength): int
    {
        if ($prefixLength % self::BYTE_SIZE === 0) {
            return 0xFF;
        }

        $shift = self::BYTE_SIZE - ($prefixLength % self::BYTE_SIZE);
        return (0xFF << $shift) & 0xFF;
    }
}
