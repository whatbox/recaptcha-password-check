<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Crypto;

enum HashType: string
{
    case SHA256 = 'sha256';
    case SHA384 = 'sha384';
    case SHA512 = 'sha512';

    public function bits(): int
    {
        return match ($this) {
            self::SHA256 => 256,
            self::SHA384 => 384,
            self::SHA512 => 512,
        };
    }

    public function digest(string $data): string
    {
        return hash($this->value, $data, binary: true);
    }
}
