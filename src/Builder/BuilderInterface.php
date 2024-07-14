<?php
declare(strict_types=1);

namespace Hyperf\Auth;

/** @immutable */
interface BuilderInterface
{
    /**
     * Appends new items to audience
     *
     * @param non-empty-string ...$audiences
     */
    public function permittedFor(string ...$audiences): BuilderInterface;

    /**
     * Configures the expiration time
     */
    public function expiresAt(int $expiration): BuilderInterface;

    /**
     * Configures the token id
     *
     * @param non-empty-string $id
     */
    public function identifiedBy(string $id): BuilderInterface;

    /**
     * Configures the time that the token was issued
     */
    public function issuedAt(int $issuedAt): BuilderInterface;

    /**
     * Configures the issuer
     *
     * @param non-empty-string $issuer
     */
    public function issuedBy(string $issuer): BuilderInterface;

    /**
     * Configures the time before which the token cannot be accepted
     */
    public function canOnlyBeUsedAfter(int $notBefore): BuilderInterface;

    /**
     * Configures the subject
     *
     * @param non-empty-string $subject
     */
    public function relatedTo(string $subject): BuilderInterface;


    /**
     * Configures header item with headers
     *
     * @param non-empty-array $headers
     *
     */
    public function withHeaders(array $headers): BuilderInterface;

    /**
     * Configures a header item
     *
     * @param non-empty-string $name
     */
    public function withHeader(string $name, mixed $value): BuilderInterface;

    /**
     * Configures claim item with params
     *
     * @param non-empty-array $params
     *
     */
    public function withClaims(array $params): BuilderInterface;

    /**
     * Configures a claim item
     *
     * @param non-empty-string $name
     *
     * @throws RegisteredClaimGiven When trying to set a registered claim.
     */
    public function withClaim(string $name, mixed $value): BuilderInterface;

    /**
     * Returns a signed token to be used
     *
     * @throws CannotEncodeContent When data cannot be converted to JSON.
     * @throws CannotSignPayload   When payload signing fails.
     * @throws InvalidKeyProvided  When issue key is invalid/incompatible.
     * @throws ConversionFailed    When signature could not be converted.
     */
    public function getToken(string $key, string $alg): string;
}
