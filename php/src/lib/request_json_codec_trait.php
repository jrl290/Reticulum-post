<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Reticulum-php is request-operated. These JSON helpers only encode and decode
// request-backed persisted state; they do not affect transport routing.

trait RequestJsonCodecTrait
{
    private static function encodeJson(array $value): string
    {
        try {
            $encoded = json_encode($value, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
            if (!is_string($encoded)) {
                throw new RuntimeException('JSON encoding failed');
            }
            return $encoded;
        } catch (\JsonException $e) {
            // Last resort: strip all non-UTF-8 from string values
            $cleaned = self::cleanStringsForJson($value);
            $encoded = json_encode($cleaned, JSON_THROW_ON_ERROR);
            if (!is_string($encoded)) {
                throw new RuntimeException('JSON encoding failed after cleaning');
            }
            return $encoded;
        }
    }

    private static function cleanStringsForJson(array $value): array
    {
        $result = [];
        foreach ($value as $k => $v) {
            if (is_string($v)) {
                $result[$k] = mb_convert_encoding($v, 'UTF-8', 'UTF-8');
            } elseif (is_array($v)) {
                $result[$k] = self::cleanStringsForJson($v);
            } else {
                $result[$k] = $v;
            }
        }
        return $result;
    }

    private static function decodeJson(string $json): array
    {
        if ($json === '' || $json === 'null') {
            return [];
        }
        try {
            $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
            return is_array($decoded) ? $decoded : [];
        } catch (\JsonException $e) {
            return [];
        }
    }
}