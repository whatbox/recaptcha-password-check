<?php

declare(strict_types=1);

namespace ReCaptcha\PasswordCheck\Crypto;

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Crypt\EC\Curves\secp256r1;

enum SupportedCurve: string
{
    case SECP256R1 = 'secp256r1';

    public function curve(): Prime
    {
        return match ($this) {
            self::SECP256R1 => new secp256r1(),
        };
    }

    public function fieldLength(): int
    {
        return $this->curve()->getLengthInBytes();
    }
}
