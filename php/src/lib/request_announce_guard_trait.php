<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

/**
 * RequestAnnounceGuardTrait — REGISTRATION-STAGE1.md §9: which announces a
 * browser row may carry.
 *
 *   I        = SHA-256(the announce's public key)[:16]
 *   owner(R) = R.identity_hash          for a signed row
 *            = R.claimed_identity_hash  for a legacy browser row, while the
 *                                       switch is off and no row has that
 *                                       identity_hash
 *            = none                     otherwise
 *   accept  <=> owner(R) != none, I = owner(R), and, for a legacy row, the
 *               announce is neither seen nor held
 *
 * It runs inside processAcceptedAnnounce(), right after
 * AnnounceValidator::validate and before anything is remembered, bound,
 * routed, cached or relayed, so both of that function's callers (an inbound
 * packet, and a cache request's replay) get it. A browser row is a signed row
 * or a row whose client is rns-js, in every mode; every other row follows
 * today's rules. A row that is gone when the announce is read owns nothing,
 * so its announce is refused as foreign, whatever the row was, and logged
 * owner=gone: a PHP node peering row that connectToPeer() replaced during an
 * exchange must not read as a foreign announce. owner=none stays for a row
 * that is there and owns nothing.
 *
 * A refusal is logged ([ANNOUNCE-FOREIGN] interface=<id8> dest=<hash>
 * identity=<8 hex> owner=<8 hex|none|gone>, [ANNOUNCE-LEGACY-REFUSED]
 * interface=<id8> dest=<hash> reason=<seen|held>), the announce's
 * inbound_packets row says 'refused', and nothing else changes: 'refused' is
 * neither 'validated' nor 'path_updated', so nothing relays it, and no reader
 * of the announce cache serves it.
 */
trait RequestAnnounceGuardTrait
{
    /** @var array<string, ?array> per-request memo of the facts §9 reads about a row */
    private array $rowRegistrationFactsCache = [];

    /**
     * The registration facts of a row, or null when there is no such row.
     *
     * @return array{proof: string, client: mixed, identity_hash: ?string, claimed_identity_hash: ?string}|null
     */
    private function rowRegistrationFacts(string $interfaceId): ?array
    {
        if (array_key_exists($interfaceId, $this->rowRegistrationFactsCache)) {
            return $this->rowRegistrationFactsCache[$interfaceId];
        }
        $stmt = $this->db->prepare(
            'SELECT registration_proof, metadata_json, identity_hash, claimed_identity_hash
               FROM interfaces WHERE interface_id = :interface_id'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();
        if (!is_array($row)) {
            return $this->rowRegistrationFactsCache[$interfaceId] = null;
        }
        $metadata = self::decodeJson((string) ($row['metadata_json'] ?? ''));

        return $this->rowRegistrationFactsCache[$interfaceId] = [
            'proof' => (string) ($row['registration_proof'] ?? 'none'),
            'client' => $metadata['client'] ?? null,
            'identity_hash' => is_string($row['identity_hash'] ?? null) && $row['identity_hash'] !== '' ? $row['identity_hash'] : null,
            'claimed_identity_hash' => is_string($row['claimed_identity_hash'] ?? null) && $row['claimed_identity_hash'] !== '' ? $row['claimed_identity_hash'] : null,
        ];
    }

    /** Drop the memo after a write that changes a row's proof or claim. */
    private function forgetRowRegistrationFacts(?string $interfaceId = null): void
    {
        if ($interfaceId === null) {
            $this->rowRegistrationFactsCache = [];
            return;
        }
        unset($this->rowRegistrationFactsCache[$interfaceId]);
    }

    /**
     * §9, for an announce that AnnounceValidator::validate has accepted on
     * row $interfaceId. Returns null to accept it, or the reason it is
     * refused (already logged).
     */
    private function announceGuardRefusal(string $interfaceId, array $packet, array $announce): ?string
    {
        $facts = $this->rowRegistrationFacts($interfaceId);
        if ($facts !== null && $facts['proof'] !== 'signed' && $facts['client'] !== 'rns-js') {
            // Not a browser row: today's rules.
            return null;
        }
        $destinationHashHex = strtolower((string) ($packet['destination_hash_hex'] ?? ''));
        $identity = strtolower((string) ($announce['identity_hash_hex'] ?? ''));
        // A row that is gone owns nothing. An announce reaches here for one
        // only when another request removed the row after this request had
        // read it: a cache request's replay, whose copy cacheRequestCopy()
        // found with its row, or an exchange still processing the row's batch
        // (§4.5 removes a legacy row; a dead PHP node peering row is
        // replaced). Until 2026-10-14 a gone row passed as no browser row: the
        // replay rewrote known_destinations, could set a path through the
        // gone row, and was relayed to every other row. Logged owner=gone, so
        // that the peering row's case does not read as a foreign announce.
        $owner = $facts === null ? null : $this->announceOwner($facts);
        if ($owner === null || !hash_equals($owner, $identity)) {
            error_log(sprintf('[ANNOUNCE-FOREIGN] interface=%s dest=%s identity=%s owner=%s',
                substr($interfaceId, 0, 8), $destinationHashHex, substr($identity, 0, 8),
                $facts === null ? 'gone' : ($owner === null ? 'none' : substr($owner, 0, 8))));

            return 'announce_foreign';
        }
        if ($facts['proof'] === 'signed') {
            return null;
        }

        // A legacy row's owner proves nothing: seen, or held elsewhere.
        $reason = null;
        if ($this->announceAlreadySeen($destinationHashHex, $announce, $packet)) {
            $reason = 'seen';
        } elseif ($this->destinationHeldByAnotherRow($destinationHashHex, $interfaceId)) {
            $reason = 'held';
        }
        if ($reason === null) {
            return null;
        }
        error_log(sprintf('[ANNOUNCE-LEGACY-REFUSED] interface=%s dest=%s reason=%s',
            substr($interfaceId, 0, 8), $destinationHashHex, $reason));

        return 'announce_legacy_' . $reason;
    }

    /**
     * owner(R), read as the announce arrives: a legacy row loses its claim
     * the moment its identity signs here.
     */
    private function announceOwner(array $facts): ?string
    {
        if ($facts['proof'] === 'signed') {
            return $facts['identity_hash'];
        }
        if ($facts['proof'] !== 'none' || $facts['client'] !== 'rns-js' || $this->enforceSignedRegistration()) {
            return null;
        }
        $claim = $facts['claimed_identity_hash'];
        if ($claim === null || preg_match('/\A[0-9a-f]{32}\z/', $claim) !== 1) {
            return null;
        }
        $stmt = $this->db->prepare('SELECT 1 FROM interfaces WHERE identity_hash = :identity_hash');
        $stmt->bindValue(':identity_hash', $claim, PDO::PARAM_STR);
        $stmt->execute();
        $signed = $stmt->fetch(PDO::FETCH_NUM) !== false;
        $stmt->closeCursor();

        return $signed ? null : $claim;
    }

    /**
     * Seen: the random blob is recorded for the destination, or the packet
     * hash is the one known_destinations remembers for it (the last accepted
     * announce's). A replay; no timer involved.
     */
    private function announceAlreadySeen(string $destinationHashHex, array $announce, array $packet): bool
    {
        $path = $this->pathEntry($destinationHashHex);
        if ($path !== null) {
            $blobs = self::decodeJson((string) ($path['random_blobs_json'] ?? '[]'));
            if (in_array((string) ($announce['random_hash_hex'] ?? ''), $blobs, true)) {
                return true;
            }
        }
        $stmt = $this->db->prepare('SELECT packet_hash_hex FROM known_destinations WHERE destination_hash_hex = :destination_hash_hex');
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, PDO::PARAM_STR);
        $stmt->execute();
        $known = $stmt->fetchColumn();
        $stmt->closeCursor();

        return is_string($known) && $known !== '' && hash_equals($known, (string) ($packet['packet_hash_hex'] ?? ''));
    }

    /**
     * Held: another row already holds the destination, by a local
     * destination or an unexpired path through it. This keeps a destination
     * that this PHP node reaches through the gateway out of a legacy row's
     * reach. Only expiry and the stale sweep, which deletes a quiet row's
     * paths, end it: a path through a row marked offline but not yet swept
     * still holds (usablePathEntry() would also ask that row to be online).
     */
    private function destinationHeldByAnotherRow(string $destinationHashHex, string $interfaceId): bool
    {
        $stmt = $this->db->prepare(
            'SELECT 1 FROM local_destinations WHERE destination_hash_hex = :destination_hash_hex AND interface_id <> :interface_id'
        );
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
        $held = $stmt->fetch(PDO::FETCH_NUM) !== false;
        $stmt->closeCursor();
        if ($held) {
            return true;
        }
        $path = $this->pathEntry($destinationHashHex);
        if ($path === null || (int) ($path['expires_at'] ?? 0) < time()) {
            return false;
        }
        $through = (string) ($path['interface_id'] ?? '');

        return $through !== '' && $through !== $interfaceId;
    }
}
