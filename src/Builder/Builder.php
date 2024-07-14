<?php

declare(strict_types=1);

namespace Hyperf\Auth;

use function array_diff;
use function array_merge;
use function in_array;

use Firebase\JWT\JWT;

/** @immutable */
final class Builder implements BuilderInterface
{
    /** @var array<non-empty-string, mixed> */
    private ?array $headers = null;

    /** @var array<non-empty-string, mixed> */
    private array $claims = [];

    public function __construct()
    {
    }

    public function permittedFor(string ...$audiences): BuilderInterface
    {
        $configured = $this->claims[Claims::AUDIENCE] ?? [];
        $toAppend   = array_diff($audiences, $configured);

        return $this->setClaim(Claims::AUDIENCE, array_merge($configured, $toAppend));
    }

    public function expiresAt(int $expiration): BuilderInterface
    {
        return $this->setClaim(Claims::EXPIRATION_TIME, $expiration);
    }

    public function identifiedBy(string $id): BuilderInterface
    {
        return $this->setClaim(Claims::ID, $id);
    }

    public function issuedAt(int $issuedAt): BuilderInterface
    {
        return $this->setClaim(Claims::ISSUED_AT, $issuedAt);
    }

    public function issuedBy(string $issuer): BuilderInterface
    {
        return $this->setClaim(Claims::ISSUER, $issuer);
    }

    public function canOnlyBeUsedAfter(int $notBefore): BuilderInterface
    {
        return $this->setClaim(Claims::NOT_BEFORE, $notBefore);
    }

    public function relatedTo(string $subject): BuilderInterface
    {
        return $this->setClaim(Claims::SUBJECT, $subject);
    }

    public function withHeaders(array $headers): BuilderInterface
    {
        foreach ($headers as $name => $value) {
            $this->withHeader($name, $value);
        }

        return $this;
    }

    public function withHeader(string $name, mixed $value): BuilderInterface
    {
        $this->headers[$name] = $value;

        return $this;
    }

    public function withClaims(array $params): BuilderInterface
    {
        foreach ($params as $name => $value) {
            $this->withClaim($name, $value);
        }

        return $this;
    }

    public function withClaim(string $name, mixed $value): BuilderInterface
    {
        if (in_array($name, Claims::ALL, true)) {
            throw ClaimGiven::forClaim($name);
        }

        return $this->setClaim($name, $value);
    }

    /** @param non-empty-string $name */
    private function setClaim(string $name, mixed $value): BuilderInterface
    {
        $this->claims[$name] = $value;

        return $this;
    }

    public function getToken(string $key, string $alg = 'HS256'): string
    {
        $token = JWT::encode($this->claims, $key, $alg, null, $this->headers);

        return $token;
    }
}
