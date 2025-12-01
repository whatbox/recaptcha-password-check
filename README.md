# reCAPTCHA Password Check – PHP

PHP port of [Google's Java API client](https://github.com/GoogleCloudPlatform/java-recaptcha-password-check-helpers) for the [reCAPTCHA Enterprise Password Check API](https://cloud.google.com/recaptcha-enterprise/docs/check-passwords).

A privacy-respecting solution to check username, password pairs against known breaches without leaking customer usernames or passwords to the breach database.

Similar to [Have I Been Pwned](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange), but a commercial API with fewer false positives by considering username and password together, instead of password alone.

## Requirements

- PHP 8.1+
- Composer

## Installation

```bash
composer install
```

## Usage

* [Enable the "reCAPTCHA Enterprise API" in your Google Cloud project](https://console.cloud.google.com/apis/api/recaptchaenterprise.googleapis.com)
* ["Create credentials" > "API key"](https://console.cloud.google.com/apis/credentials)

```php
<?php

use ReCaptcha\PasswordCheck\Client\ReCaptchaPasswordCheckClient;
use ReCaptcha\PasswordCheck\PasswordCheckVerification;

$verification = PasswordCheckVerification::create($username, $password);

$client = new ReCaptchaPasswordCheckClient();
$result = $client->completeVerification(
    $projectId,
    $apiKey,
    $verification,

    // Optional: If you use reCAPTCHA bot protection, you can attach this password check to the
    // reCaptcha Token and feed Google additional data in exchange for more accurate bot scores
    // expectedAction: 'login',
    // eventOverrides: [
    //     'siteKey' => $siteKey,
    //     'token' => $recaptchaToken,
    // ]
);

if ($result->areCredentialsLeaked()) {
    // Prompt the user to reset their password.
}
```

## Running tests

```bash
composer test
```

## Project structure

- `src/Crypto` – Elliptic-curve primitive, hash type enum, and supported curves.
- `src/Utils` – Username canonicalization, PHP Scrypt, and bit-prefix helpers.
- `src/Client` – High-level HTTP client for Google reCAPTCHA Password Check.
- `tests/` – PHPUnit test suite mirroring the upstream reference coverage.

## License

Apache 2.0 – consistent with the upstream Google reference implementations.
