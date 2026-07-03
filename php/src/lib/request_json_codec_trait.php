<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Reticulum-php is request-operated. These JSON helpers only encode and decode
// request-backed persisted state; they do not affect transport routing.

trait RequestJsonCodecTrait
{
    private static function encodeJson(array $value): string
    {
        $encoded = json_encode($value, JSON_THROW_ON_ERROR);
        if (!is_string($encoded)) {
            throw new RuntimeException('JSON encoding failed');
        }

        return $encoded;
    }

    private static function decodeJson(string $json): array
    {
        $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        return is_array($decoded) ? $decoded : [];
    }
}