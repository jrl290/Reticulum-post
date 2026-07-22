<?php

declare(strict_types=1);

namespace ReticulumPhp;

/**
 * Minimal PacketParser stub for tests.
 * The real class lives in index.php.
 */
class PacketParser
{
    /** @return array{packet_type:int, destination_hash_hex:string, ...} */
    public static function parseRaw(string $raw): array
    {
        if (strlen($raw) < 2) {
            throw new \RuntimeException('Packet too short');
        }
        $flags = ord($raw[0]);
        return [
            'packet_type'       => $flags & 0x03,
            'destination_type'  => ($flags >> 2) & 0x03,
            'transport_type'    => ($flags >> 4) & 0x03,
            'header_type'       => ($flags >> 6) & 0x03,
            'context_flag'      => ($flags >> 5) & 0x01,
            'hops'              => ord($raw[1]),
            'destination_hash_hex' => bin2hex(substr($raw, 2, 16)),
            'context'           => ord($raw[18] ?? "\x00"),
            'transport_id_hex'  => null,
            'packet_hash_hex'   => bin2hex(hash('sha256', $raw, true)),
            'truncated_hash_hex'=> bin2hex(substr(hash('sha256', $raw, true), 0, 8)),
            'payload_base64'    => base64_encode(substr($raw, 19)),
            'normalized_raw_base64' => base64_encode($raw),
        ];
    }
}
