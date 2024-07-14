<?php
declare(strict_types=1);

namespace Hyperf\Auth;

use InvalidArgumentException;
use Hyperf\Auth\Exception;

use function sprintf;

final class ClaimGiven extends InvalidArgumentException implements Exception
{
    private const DEFAULT_MESSAGE = 'Builder#withClaim() is meant to be used for non-registered claims, '
                                  . 'check the documentation on how to set claim "%s"';

    public static function forClaim(string $name): self
    {
        return new self(sprintf(self::DEFAULT_MESSAGE, $name));
    }
}
