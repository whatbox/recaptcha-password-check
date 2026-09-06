# reCAPTCHA Password Check – PHP

PHP port of [Google's Java API client](https://github.com/GoogleCloudPlatform/java-recaptcha-password-check-helpers) for the [reCAPTCHA Enterprise Password Check API](https://cloud.google.com/recaptcha-enterprise/docs/check-passwords).

A privacy-respecting solution to check username, password pairs against known breaches without leaking customer usernames or passwords to the breach database.

Similar to [Have I Been Pwned](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange), but a commercial API with fewer false positives by considering username and password together, instead of password alone.


## Requirements

- PHP 8.1+
- [ext-scrypt](https://github.com/DomBlack/php-scrypt) is optional, but recommended for performance


## Installation

```bash
composer require whatbox/recaptcha-password-check
```

## Usage

* [Enable the "reCAPTCHA Enterprise API" in your Google Cloud project](https://console.cloud.google.com/apis/api/recaptchaenterprise.googleapis.com)
* ["Create credentials" > "API key"](https://console.cloud.google.com/apis/credentials)

```php
<?php

use ReCaptcha\PasswordCheck\Client\ReCaptchaPasswordCheckClient;

$client = new ReCaptchaPasswordCheckClient($projectId, $apiKey);
$result = $client->checkPassword(
    $username,
    $password,

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


## Granular Usage

```php
<?php

use ReCaptcha\PasswordCheck\Client\ReCaptchaPasswordCheckClient;
use ReCaptcha\PasswordCheck\PasswordCheckVerification;

$client = new ReCaptchaPasswordCheckClient($projectId, $apiKey);

// Hashing and crypto (CPU bound)
$verification = PasswordCheckVerification::create($usernameOrEmail, $password);

// Sending to Google (Network latency bound)
$result = $client->completeVerification($verification);

if ($result->areCredentialsLeaked()) {
    // Prompt the user to reset their password.
}
```

The `$verification` object holds the private key needed to decrypt Google's response, so it must be
the same instance for both phases and must never be serialized to shared storage.


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
