<?php
/**
 * REGISTRATION-STAGE1.md §9 and §14's announce_row_identity_test.php: which
 * announces a browser row may carry, through the real Storage (SQLite) and
 * real signed RNS announces fed to the real inbound path.
 *
 *   owner(R) = R.identity_hash          for a signed row
 *            = R.claimed_identity_hash  for a legacy browser row, while the
 *                                       switch is off and no row has that
 *                                       identity_hash
 *            = none                     otherwise
 *   accept  <=> owner(R) != none, I = owner(R), and, for a legacy row, the
 *               announce is neither seen nor held
 *
 * Covered:
 *  (1) a victim's announce replayed through another browser row (signed, or
 *      legacy with a made-up claim, with none, or an old one in a transit
 *      mode), at hops 0 and 5, moves neither its local destination nor its
 *      packets; a dropped announce leaves known_destinations untouched and is
 *      neither cached nor forwarded;
 *  (2) a legacy row gets no local destination for one held elsewhere (an
 *      unexpired path through the gateway, also while that row is marked
 *      offline and not yet swept; another row's local destination) or seen
 *      (its random blob; the packet hash known_destinations remembers);
 *  (3) a CACHE_REQUEST for a legacy browser row's own earlier announce, which
 *      §9 now finds seen, queues no announce on any row and its verdict is
 *      miss; a signed row's and a gateway row's are replayed as today;
 *  (4) a row registered after a refused copy of D's announce is seeded with
 *      D's last accepted copy, with D's path and without it;
 *  (5) a browser's own announces still make local destinations and are
 *      forwarded; a gateway row's and a PHP node peering row's behave as
 *      today;
 *  (6) owner(R) is read as the announce arrives (a legacy row loses its claim
 *      the moment its identity signs here); with the switch on a legacy
 *      browser row owns nothing;
 *  (7) the stated residual (§16 item 3): once the stale sweep has removed the
 *      path through a peering row, an older announce through a legacy row
 *      claiming the identity makes a local destination there, while the
 *      newest one the node remembers is refused; an expired path no longer
 *      counts as held;
 *  (8) past the inbound TTL, maintenance keeps an announce's accepted copy,
 *      never a refused replay of it that ties on hops and interface;
 *  (9) once §4.5 has removed a legacy row, keeping its inbound history, a
 *      CACHE_REQUEST for its copy of an announce is a miss: no announce is
 *      queued, no path leads to the removed row, known_destinations is as
 *      it was;
 *  (10) a path request is answered from such a copy exactly as before the
 *      row went: when maintenance kept the removed row's copy as the only
 *      one of an announce a live path through another row holds (a link
 *      proof set the path's hop count to that copy's), the PATH_RESPONSE is
 *      the same bytes, to the same row, and no path or known_destinations
 *      row changes, while a cache request for it is still a miss;
 *  (11) a cache request whose copy's row another request removes after the
 *      copy is looked up and before §9 reads the row (a legacy row §4.5
 *      removes as its identity signs; a dead PHP node peering row replaced)
 *      is refused, [ANNOUNCE-FOREIGN] ... owner=none: a miss, no announce
 *      queued, no path, no local destination, known_destinations as it was;
 *      with its row there the peering row's copy is replayed as today, and a
 *      gateway row's and a browser row's (legacy, signed) own announces in a
 *      later request are as today.
 *
 * Today (before Stage 1) the replay moves the local destination, and the
 * cache replay is relayed to every other row. On code without signed
 * registration the signed cases are skipped and counted as one failure.
 *
 * Run: php php/tests/announce_row_identity_test.php
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/index.php';
require_once __DIR__ . '/stubs/registration_fixture.php';
require_once __DIR__ . '/stubs/announce_fixture.php';

use ReticulumPhp\Storage;

$pass = 0;
$fail = 0;
function check(string $label, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) {
        $pass++;
        echo "  ok   $label\n";
    } else {
        $fail++;
        echo "  FAIL $label" . ($detail !== '' ? "\n         $detail" : '') . "\n";
    }
}

function q(PDO $db, string $sql, array $args = []): array
{
    $st = $db->prepare($sql);
    $st->execute($args);

    return $st->fetchAll(PDO::FETCH_ASSOC);
}

function pathOf(PDO $db, string $dest): ?array
{
    return q($db, 'SELECT * FROM path_entries WHERE destination_hash_hex = :d', [':d' => $dest])[0] ?? null;
}

/** The row holding the destination as a local destination, or null. */
function localOf(PDO $db, string $dest): ?string
{
    return q($db, 'SELECT interface_id FROM local_destinations WHERE destination_hash_hex = :d', [':d' => $dest])[0]['interface_id'] ?? null;
}

function knownOf(PDO $db, string $dest): ?array
{
    return q($db, 'SELECT * FROM known_destinations WHERE destination_hash_hex = :d', [':d' => $dest])[0] ?? null;
}

/** [announce_status, announce_reason] of the newest stored copy of a packet (received on $iface, if given). */
function verdictOf(PDO $db, string $packetHash, ?string $iface = null): array
{
    $sql = 'SELECT announce_status, announce_reason FROM inbound_packets WHERE packet_hash_hex = :h'
        . ($iface === null ? '' : ' AND interface_id = :i') . ' ORDER BY packet_record_id DESC LIMIT 1';
    $row = q($db, $sql, $iface === null ? [':h' => $packetHash] : [':h' => $packetHash, ':i' => $iface])[0] ?? [];

    return [$row['announce_status'] ?? null, $row['announce_reason'] ?? null];
}

/** Every announce queued on any row: [interface_id, packet hash]. */
function announcesQueued(PDO $db): array
{
    return array_map(
        static fn (array $r): array => [$r['interface_id'], AnnounceFixture::packetHash((string) base64_decode((string) $r['packet_base64']))],
        q($db, "SELECT interface_id, packet_base64 FROM outbound_packets WHERE queue_reason = 'relay_announce' ORDER BY packet_id")
    );
}

/** Feed raw packets through $iface and return the error_log lines written. */
function feed(Storage $s, string $iface, string ...$raws): string
{
    [, $log] = RegFixture::capture(static fn () => AnnounceFixture::ingest($s, $iface, ...$raws));

    return $log;
}

/** A signed browser row through the real code, or null where there is no signed registration. */
function signedRow(Storage $s, array $identity): ?string
{
    if (!method_exists($s, 'issueChallenge')) {
        return null;
    }
    [$answer] = RegFixture::capture(static fn () => RegFixture::register($s, $identity));

    return is_array($answer) ? (string) $answer['interface_id'] : null;
}

function legacyRow(Storage $s, array $metadata, string $name = 'legacy'): string
{
    [$answer] = RegFixture::capture(static fn () => $s->registerInterface($name, 1000000, 500, $metadata));
    if (!is_array($answer)) {
        throw new RuntimeException('legacy registration refused: ' . json_encode(RegFixture::outcome($answer)));
    }

    return (string) $answer['interface_id'];
}

function foreignLine(string $row, string $dest, array $identity, string $owner): string
{
    return sprintf('[ANNOUNCE-FOREIGN] interface=%s dest=%s identity=%s owner=%s', substr($row, 0, 8), $dest, substr($identity['hash_hex'], 0, 8), $owner);
}

function legacyRefusedLine(string $row, string $dest, string $reason): string
{
    return sprintf('[ANNOUNCE-LEGACY-REFUSED] interface=%s dest=%s reason=%s', substr($row, 0, 8), $dest, $reason);
}

function browser(?string $claim = null): array
{
    return $claim === null ? ['client' => 'rns-js', 'mode' => 1] : ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $claim];
}

/**
 * A PATH_REQUEST for a destination, as Transport.request_path() sends it: DATA
 * to the PLAIN destination rnstransport.path.request, carrying the destination
 * hash and a fresh tag.
 */
function pathRequest(string $destHex): string
{
    $control = substr(hash('sha256', substr(hash('sha256', 'rnstransport.path.request', true), 0, 10), true), 0, 16);

    return chr(0x08) . chr(0) . $control . chr(0x00) . (string) hex2bin($destHex) . random_bytes(16);
}

/** A path request for $dest through $row: its verdict, and every packet it queued. */
function pathAnswer(Storage $s, PDO $db, string $row, string $dest): array
{
    $db->exec('DELETE FROM outbound_packets');
    $request = pathRequest($dest);
    feed($s, $row, $request);

    return [
        'verdict' => verdictOf($db, AnnounceFixture::packetHash($request)),
        'queued' => q($db, 'SELECT interface_id, queue_reason, packet_base64 FROM outbound_packets ORDER BY packet_id'),
    ];
}

$tmp = sys_get_temp_dir() . '/announce-row-identity-' . bin2hex(random_bytes(4));
mkdir($tmp, 0775, true);
register_shutdown_function(static function () use ($tmp): void {
    foreach (glob($tmp . '/*') ?: [] as $file) {
        unlink($file);
    }
    rmdir($tmp);
});
$dbPath = $tmp . '/node.sqlite';
$node = RegFixture::storage([], $dbPath);
$db = RegFixture::db($node);
$signedHere = method_exists($node, 'issueChallenge');
if (!$signedHere) {
    check("Stage 1's signed registration exists", false, 'no Storage::issueChallenge(): every signed case below is skipped');
}
$cachedAnnounce = new ReflectionMethod($node, 'cachedAnnounceRecordByPacketHash');
$cacheRequestCopy = new ReflectionMethod($node, 'cacheRequestCopy');

// Rows every section uses.
$third = legacyRow($node, browser(), 'third party'); // sends DATA and cache requests
$gatewayRow = legacyRow($node, RegFixture::pollGatewayMetadata(), 'gateway');
$peerRow = legacyRow($node, RegFixture::phpPeerMetadata('https://peer.example/reticulum'), 'peer PHP node');

echo "(1) a victim's announce replayed through another browser row moves nothing\n";
$victims = [];
$legacyVictim = RegFixture::identity();
$victims['legacy victim'] = [$legacyVictim, legacyRow($node, browser($legacyVictim['hash_hex']))];
if ($signedHere) {
    $signedVictim = RegFixture::identity();
    $victims['signed victim'] = [$signedVictim, (string) signedRow($node, $signedVictim)];
}
$madeUp = bin2hex(random_bytes(16));
$oldTransitClaim = bin2hex(random_bytes(16));
$oldTransitRow = legacyRow($node, browser($oldTransitClaim), 'old transit');
// A legacy browser row in a transit mode, as a registration before Stage 1
// left it (§4.6 now refuses modes 3, 5 and 6): the rule runs in every mode.
$db->prepare('UPDATE interfaces SET metadata_json = :m WHERE interface_id = :i')
    ->execute([':m' => json_encode(['client' => 'rns-js', 'mode' => 6, 'identity_hash' => $oldTransitClaim]), ':i' => $oldTransitRow]);
$attackers = [
    'legacy row, made-up claim' => [legacyRow($node, browser($madeUp)), substr($madeUp, 0, 8)],
    'legacy row, no claim' => [legacyRow($node, browser()), 'none'],
    'old legacy row in mode 6' => [$oldTransitRow, substr($oldTransitClaim, 0, 8)],
];
if ($signedHere) {
    $signedAttacker = RegFixture::identity();
    $attackers['another signed row'] = [(string) signedRow($node, $signedAttacker), substr($signedAttacker['hash_hex'], 0, 8)];
}

$victimAnnounces = [];
foreach ($victims as $who => [$victim, $victimRow]) {
    $a = AnnounceFixture::announce($victim, 'lxmf.delivery', 0, null, 'victim-app-data', time() - 30);
    $victimAnnounces[$who] = $a;
    $log = feed($node, $victimRow, $a['raw']);
    check("[$who] its own announce makes its local destination on its row",
        localOf($db, $a['dest_hex']) === $victimRow && !str_contains($log, '[ANNOUNCE-'), trim($log));
    $pathBefore = pathOf($db, $a['dest_hex']);
    foreach ($attackers as $what => [$row, $owner]) {
        foreach ([0, 5] as $hops) {
            $log = feed($node, $row, AnnounceFixture::withHops($a['raw'], $hops));
            check("[$who; $what; hops $hops] dropped: [ANNOUNCE-FOREIGN] interface dest identity owner=$owner",
                str_contains($log, foreignLine($row, $a['dest_hex'], $victim, $owner)), trim($log));
            check("[$who; $what; hops $hops] its verdict is refused, announce_foreign",
                verdictOf($db, $a['packet_hash_hex'], $row) === ['refused', 'announce_foreign'], json_encode(verdictOf($db, $a['packet_hash_hex'], $row)));
        }
        check("[$who; $what] the local destination stays on the victim's row", localOf($db, $a['dest_hex']) === $victimRow, (string) localOf($db, $a['dest_hex']));
        check("[$who; $what] the path is untouched", pathOf($db, $a['dest_hex']) == $pathBefore);
    }
    $db->exec('DELETE FROM outbound_packets');
    feed($node, $third, AnnounceFixture::data($a['dest_hex']));
    $queued = q($db, 'SELECT interface_id FROM outbound_packets');
    check("[$who] a third party's DATA to it is queued to its row only",
        count($queued) === 1 && $queued[0]['interface_id'] === $victimRow, json_encode($queued));
}

// A new announce of the victim (a fresh blob, other app_data) through
// another row is dropped whole.
$who = $signedHere ? 'signed victim' : 'legacy victim';
[$victim, $victimRow] = $victims[$who];
$d = $victimAnnounces[$who]['dest_hex'];
[$attackerRow] = $attackers['legacy row, made-up claim'];
$knownBefore = knownOf($db, $d);
$pathBefore = pathOf($db, $d);
$refusedCopy = AnnounceFixture::announce($victim, 'lxmf.delivery', 0, null, 'not-to-be-remembered', time());
$db->exec('DELETE FROM outbound_packets');
$log = feed($node, $attackerRow, $refusedCopy['raw']);
check("[$who] a new announce of it through another row is refused",
    verdictOf($db, $refusedCopy['packet_hash_hex']) === ['refused', 'announce_foreign'], trim($log));
check('a dropped announce leaves known_destinations untouched (packet hash, key, app_data, ratchet, updated_at)',
    knownOf($db, $d) === $knownBefore, json_encode(knownOf($db, $d)));
check('...adds nothing to the path, its random blobs included', pathOf($db, $d) == $pathBefore);
check('...is not the announce cache: no path response or cache request serves it',
    $cachedAnnounce->invoke($node, $refusedCopy['packet_hash_hex']) === null);
check('...and is not forwarded: no announce queued on any row', announcesQueued($db) === [], json_encode(announcesQueued($db)));
$unknown = AnnounceFixture::announce(RegFixture::identity(), 'lxmf.delivery');
feed($node, $attackerRow, $unknown['raw']);
check('a foreign announce of a destination never heard here leaves no path, no key, no local destination',
    pathOf($db, $unknown['dest_hex']) === null && knownOf($db, $unknown['dest_hex']) === null && localOf($db, $unknown['dest_hex']) === null);

echo "\n(2) a legacy row gets no local destination for one held elsewhere or seen\n";
$native = RegFixture::identity(); // a native user, reached through the gateway
$aN0 = AnnounceFixture::announce($native, 'lxmf.delivery', 3, null, 'native-earlier', time() - 90);
$aN = AnnounceFixture::announce($native, 'lxmf.delivery', 3, null, 'native', time() - 60);
$log = feed($node, $gatewayRow, $aN0['raw']) . feed($node, $gatewayRow, $aN['raw']);
check("a gateway row's announce is as today: a path through it, no local destination, no [ANNOUNCE-] line",
    (pathOf($db, $aN['dest_hex'])['interface_id'] ?? null) === $gatewayRow && localOf($db, $aN['dest_hex']) === null
    && !str_contains($log, '[ANNOUNCE-'), trim($log));
$squatter = legacyRow($node, browser($native['hash_hex']));
$knownN = knownOf($db, $aN['dest_hex']);
// An announce of the native user's not yet heard here, captured elsewhere.
$aN2 = AnnounceFixture::announce($native, 'lxmf.delivery', 0, null, 'captured', time());
$log = feed($node, $squatter, $aN2['raw']);
check('held by a usable path through another row (the gateway): [ANNOUNCE-LEGACY-REFUSED] reason=held',
    str_contains($log, legacyRefusedLine($squatter, $aN['dest_hex'], 'held'))
    && verdictOf($db, $aN2['packet_hash_hex'], $squatter) === ['refused', 'announce_legacy_held'], trim($log));
check('...no local destination, the path still through the gateway, known_destinations untouched',
    localOf($db, $aN['dest_hex']) === null && (pathOf($db, $aN['dest_hex'])['interface_id'] ?? null) === $gatewayRow
    && knownOf($db, $aN['dest_hex']) === $knownN);
$log = feed($node, $squatter, AnnounceFixture::withHops($aN0['raw'], 0));
check('a replay of an earlier announce the gateway brought (its blob recorded, its packet hash no longer remembered): reason=seen',
    (knownOf($db, $aN['dest_hex'])['packet_hash_hex'] ?? null) === $aN['packet_hash_hex']
    && str_contains($log, legacyRefusedLine($squatter, $aN['dest_hex'], 'seen'))
    && verdictOf($db, $aN0['packet_hash_hex'], $squatter) === ['refused', 'announce_legacy_seen']
    && localOf($db, $aN['dest_hex']) === null, trim($log));
$log = feed($node, $squatter, AnnounceFixture::withHops($aN['raw'], 0));
check('a replay of the latest announce the gateway brought: reason=seen',
    str_contains($log, legacyRefusedLine($squatter, $aN['dest_hex'], 'seen'))
    && verdictOf($db, $aN['packet_hash_hex'], $squatter) === ['refused', 'announce_legacy_seen']
    && localOf($db, $aN['dest_hex']) === null, trim($log));
$db->prepare('DELETE FROM path_entries WHERE destination_hash_hex = :d')->execute([':d' => $aN['dest_hex']]);
$log = feed($node, $squatter, AnnounceFixture::withHops($aN['raw'], 0));
check('with no path left, the packet hash known_destinations remembers still makes it seen',
    str_contains($log, legacyRefusedLine($squatter, $aN['dest_hex'], 'seen'))
    && localOf($db, $aN['dest_hex']) === null && pathOf($db, $aN['dest_hex']) === null, trim($log));
// A path through a row marked offline but not yet swept still holds: only
// expiry and the stale sweep end it (§9).
$quietGateway = legacyRow($node, RegFixture::pollGatewayMetadata(), 'quiet gateway');
$native2 = RegFixture::identity();
$aQ = AnnounceFixture::announce($native2, 'lxmf.delivery', 3, null, '', time() - 60);
feed($node, $quietGateway, $aQ['raw']);
$db->prepare("UPDATE interfaces SET status = 'offline' WHERE interface_id = :i")->execute([':i' => $quietGateway]);
$squatter2 = legacyRow($node, browser($native2['hash_hex']));
$aQ2 = AnnounceFixture::announce($native2, 'lxmf.delivery', 0, null, 'captured', time());
$log = feed($node, $squatter2, $aQ2['raw']);
check('held by an unexpired path through a row marked offline but not yet swept: reason=held',
    str_contains($log, legacyRefusedLine($squatter2, $aQ['dest_hex'], 'held')) && localOf($db, $aQ['dest_hex']) === null, trim($log));
$own = RegFixture::identity();
$ownRow = legacyRow($node, browser($own['hash_hex']));
$aO = AnnounceFixture::announce($own, 'lxmf.delivery', 0, null, '', time() - 30);
// Another row holds the destination as a local destination, with no path
// anywhere, as today's code can leave one at the deploy.
$db->prepare('INSERT INTO local_destinations (destination_hash_hex, interface_id, registered_at) VALUES (:d, :i, :t)')
    ->execute([':d' => $aO['dest_hex'], ':i' => $third, ':t' => time()]);
$log = feed($node, $ownRow, $aO['raw']);
check("held by another row's local destination: reason=held, and the local destination stays there",
    str_contains($log, legacyRefusedLine($ownRow, $aO['dest_hex'], 'held')) && localOf($db, $aO['dest_hex']) === $third
    && pathOf($db, $aO['dest_hex']) === null, trim($log));

echo "\n(3) a cache request replays only what §9 accepts\n";
$browserB = RegFixture::identity();
$browserBRow = legacyRow($node, browser($browserB['hash_hex']));
$aB = AnnounceFixture::announce($browserB, 'lxmf.delivery', 0, null, 'b', time() - 30);
feed($node, $browserBRow, $aB['raw']);
check("(precondition) a legacy browser's own announce makes its local destination", localOf($db, $aB['dest_hex']) === $browserBRow);
$knownB = knownOf($db, $aB['dest_hex']);
$db->exec('DELETE FROM outbound_packets');
$request = AnnounceFixture::cacheRequest($aB['packet_hash_hex']);
$log = feed($node, $third, $request);
check("a CACHE_REQUEST for the legacy row's own earlier announce: §9 finds it seen",
    str_contains($log, legacyRefusedLine($browserBRow, $aB['dest_hex'], 'seen')), trim($log));
check('...its verdict is miss (cached_announce_not_relayed)',
    verdictOf($db, AnnounceFixture::packetHash($request)) === ['miss', 'cached_announce_not_relayed'], json_encode(verdictOf($db, AnnounceFixture::packetHash($request))));
check('...no announce is queued on any row (no relay_announce)', announcesQueued($db) === [], json_encode(announcesQueued($db)));
check('...the local destination and known_destinations are as they were',
    localOf($db, $aB['dest_hex']) === $browserBRow && knownOf($db, $aB['dest_hex']) === $knownB);
$aG = AnnounceFixture::announce(RegFixture::identity(), 'lxmf.delivery', 2, null, 'g', time() - 30);
feed($node, $gatewayRow, $aG['raw']);
$db->exec('DELETE FROM outbound_packets');
$request = AnnounceFixture::cacheRequest($aG['packet_hash_hex']);
feed($node, $third, $request);
check("a cache request for a gateway row's announce is replayed as today, to the browser rows",
    verdictOf($db, AnnounceFixture::packetHash($request))[0] === 'replayed'
    && in_array([$third, $aG['packet_hash_hex']], announcesQueued($db), true), json_encode(verdictOf($db, AnnounceFixture::packetHash($request))));
if ($signedHere) {
    [$signedVictim, $signedVictimRow] = $victims['signed victim'];
    $db->exec('DELETE FROM outbound_packets');
    $request = AnnounceFixture::cacheRequest($victimAnnounces['signed victim']['packet_hash_hex']);
    $log = feed($node, $third, $request);
    check("a cache request for a signed row's own earlier announce is replayed (seen and held are a legacy row's rules)",
        verdictOf($db, AnnounceFixture::packetHash($request))[0] === 'replayed' && !str_contains($log, '[ANNOUNCE-')
        && in_array([$third, $victimAnnounces['signed victim']['packet_hash_hex']], announcesQueued($db), true), trim($log));
}

echo "\n(4) a row registered after a refused copy of D's announce is seeded with D's last accepted copy\n";
$newestStatus = q($db, 'SELECT announce_status FROM inbound_packets WHERE destination_hash_hex = :d AND packet_type = 1 ORDER BY packet_record_id DESC LIMIT 1', [':d' => $d])[0]['announce_status'] ?? null;
check("(precondition) D's newest stored announce is the refused one", $newestStatus === 'refused', (string) $newestStatus);
$seededCopy = static function (string $row) use ($db, $d): ?string {
    $queued = q($db, "SELECT packet_base64 FROM outbound_packets WHERE interface_id = :i AND destination_hash_hex = :d AND queue_reason = 'relay_announce'", [':i' => $row, ':d' => $d]);

    return count($queued) === 1 ? AnnounceFixture::packetHash((string) base64_decode((string) $queued[0]['packet_base64'])) : null;
};
$late = legacyRow($node, browser(), 'late');
$node->seedInterfaceIfNew($late);
check("with D's path: seeded with D's last accepted copy, not the refused one",
    $seededCopy($late) === $victimAnnounces[$who]['packet_hash_hex'], (string) $seededCopy($late));
// With D's path gone, as the stale sweep leaves it, seeding takes D's newest
// copy: the newest accepted one (until Stage 1 the newest whatever its status).
$db->prepare('DELETE FROM path_entries WHERE destination_hash_hex = :d')->execute([':d' => $d]);
$later = legacyRow($node, browser(), 'later');
$node->seedInterfaceIfNew($later);
check("without D's path: seeded with D's newest accepted copy, not the newer refused one",
    $seededCopy($later) === $victimAnnounces[$who]['packet_hash_hex'], (string) $seededCopy($later));

echo "\n(5) a browser's own announces still make local destinations; gateway rows as today\n";
if ($signedHere) {
    $browserS = RegFixture::identity();
    $browserSRow = (string) signedRow($node, $browserS);
    foreach (['lxmf.delivery', 'rfed.delivery'] as $name) {
        $db->exec('DELETE FROM outbound_packets');
        $a = AnnounceFixture::announce($browserS, $name, 0, null, 'x');
        $log = feed($node, $browserSRow, $a['raw']);
        check("a signed browser's own $name announce makes its local destination on its row, and is forwarded",
            localOf($db, $a['dest_hex']) === $browserSRow && !str_contains($log, '[ANNOUNCE-')
            && in_array([$third, $a['packet_hash_hex']], announcesQueued($db), true), trim($log));
    }
}
$browserL = RegFixture::identity();
$browserLRow = legacyRow($node, browser($browserL['hash_hex']));
foreach (['lxmf.delivery', 'rfed.delivery'] as $name) {
    $db->exec('DELETE FROM outbound_packets');
    $a = AnnounceFixture::announce($browserL, $name, 0, null, 'x');
    $log = feed($node, $browserLRow, $a['raw']);
    check("a legacy browser's own $name announce (nobody holds it, never heard) makes its local destination, and is forwarded",
        localOf($db, $a['dest_hex']) === $browserLRow && !str_contains($log, '[ANNOUNCE-')
        && in_array([$third, $a['packet_hash_hex']], announcesQueued($db), true), trim($log));
}
$a = AnnounceFixture::announce($browserL, 'lxmf.delivery', 0, null, 'reload', time() + 1);
$log = feed($node, $browserLRow, $a['raw']);
check("its next announce of the same destination through its own row still passes (held only counts other rows)",
    verdictOf($db, $a['packet_hash_hex'])[0] === 'path_updated' && localOf($db, $a['dest_hex']) === $browserLRow, trim($log));
foreach (['gateway row (rns-post-interface, mode 6)' => $gatewayRow, 'PHP node peering row (reticulum-php)' => $peerRow] as $kind => $row) {
    $db->exec('DELETE FROM outbound_packets');
    $a = AnnounceFixture::announce(RegFixture::identity(), 'lxmf.delivery', 1);
    $log = feed($node, $row, $a['raw']);
    check("a $kind carries another identity's announce as today: path, no local destination, forwarded, no [ANNOUNCE-] line",
        (pathOf($db, $a['dest_hex'])['interface_id'] ?? null) === $row && localOf($db, $a['dest_hex']) === null
        && verdictOf($db, $a['packet_hash_hex'])[0] === 'path_updated'
        && in_array([$third, $a['packet_hash_hex']], announcesQueued($db), true) && !str_contains($log, '[ANNOUNCE-'), trim($log));
}

echo "\n(6) owner(R) is read as the announce arrives; the switch\n";
if ($signedHere) {
    $signing = RegFixture::identity();
    $oldTab = legacyRow($node, browser($signing['hash_hex']), 'old tab');
    $aS = AnnounceFixture::announce($signing, 'lxmf.delivery', 0, null, '', time() - 20);
    feed($node, $oldTab, $aS['raw']);
    check("(precondition) the legacy row's own announce makes its local destination", localOf($db, $aS['dest_hex']) === $oldTab);
    // The identity signs here; §4.5's removal of the legacy row fails at its
    // first step, so the row stays (the bind still answers, §4.5).
    $db->exec("CREATE TRIGGER keep_old_tab BEFORE DELETE ON local_destinations WHEN OLD.interface_id = '{$oldTab}'
               BEGIN SELECT RAISE(ABORT, 'kept by this test'); END");
    $signedTab = signedRow($node, $signing);
    $db->exec('DROP TRIGGER keep_old_tab');
    check('(precondition) the signed bind answered and the legacy row is still there',
        $signedTab !== null && count(q($db, 'SELECT 1 FROM interfaces WHERE interface_id = :i', [':i' => $oldTab])) === 1);
    $aS2 = AnnounceFixture::announce($signing, 'lxmf.delivery', 0, null, '', time() - 10);
    $log = feed($node, $oldTab, $aS2['raw']);
    check('the legacy row lost its claim the moment its identity signed: [ANNOUNCE-FOREIGN] owner=none',
        str_contains($log, foreignLine($oldTab, $aS['dest_hex'], $signing, 'none'))
        && verdictOf($db, $aS2['packet_hash_hex']) === ['refused', 'announce_foreign'], trim($log));
    $aS3 = AnnounceFixture::announce($signing, 'lxmf.delivery', 0, null, '', time());
    $log = feed($node, (string) $signedTab, $aS3['raw']);
    check("the signed row's own announce takes the local destination",
        localOf($db, $aS['dest_hex']) === $signedTab && !str_contains($log, '[ANNOUNCE-'), trim($log));
}
$switching = RegFixture::identity();
$switchingRow = legacyRow($node, browser($switching['hash_hex']));
$switchedOn = RegFixture::storage(['enforce_signed_registration' => true], $dbPath);
$aW = AnnounceFixture::announce($switching, 'lxmf.delivery', 0, null, '', time() - 10);
$log = feed($switchedOn, $switchingRow, $aW['raw']);
check("with enforce_signed_registration on, a legacy browser row's own announce is foreign: owner=none",
    str_contains($log, foreignLine($switchingRow, $aW['dest_hex'], $switching, 'none')) && localOf($db, $aW['dest_hex']) === null, trim($log));
$aW2 = AnnounceFixture::announce($switching, 'lxmf.delivery', 0, null, '', time());
$log = feed($node, $switchingRow, $aW2['raw']);
check('with it off, the same row\'s next announce makes its local destination', localOf($db, $aW['dest_hex']) === $switchingRow, trim($log));
unset($switchedOn);

echo "\n(7) the stated residual (§16 item 3)\n";
$quiet = RegFixture::identity(); // reached this node only through the peering row
$older = AnnounceFixture::announce($quiet, 'lxmf.delivery', 2, null, 'older', time() - 120);
$newer = AnnounceFixture::announce($quiet, 'lxmf.delivery', 2, null, 'newer', time() - 60);
feed($node, $peerRow, $older['raw']);
feed($node, $peerRow, $newer['raw']);
check('(precondition) both came through the peering row: the path is through it, and the newer is the one remembered',
    (pathOf($db, $newer['dest_hex'])['interface_id'] ?? null) === $peerRow
    && (knownOf($db, $newer['dest_hex'])['packet_hash_hex'] ?? null) === $newer['packet_hash_hex']);
// The peering row goes quiet and the stale sweep removes its paths, their
// random blobs with them.
$db->prepare("UPDATE interfaces SET status = 'offline', last_seen_at = 1, updated_at = 1 WHERE interface_id = :i")->execute([':i' => $peerRow]);
$summary = [];
(new ReflectionMethod($node, 'deleteOrphanedPathsForStaleInterfaces'))->invokeArgs($node, [time(), 'sqlite', &$summary]);
(new ReflectionMethod($node, 'deleteOrphanedLocalDestinationsForStaleInterfaces'))->invoke($node, time(), 'sqlite');
check('(precondition) the stale sweep removed the path through the peering row', pathOf($db, $newer['dest_hex']) === null);
$claimer = legacyRow($node, browser($quiet['hash_hex']));
$log = feed($node, $claimer, AnnounceFixture::withHops($newer['raw'], 0));
check('the newest announce the node remembers, through a legacy row claiming the identity, is refused: reason=seen',
    str_contains($log, legacyRefusedLine($claimer, $newer['dest_hex'], 'seen')) && localOf($db, $newer['dest_hex']) === null, trim($log));
$log = feed($node, $claimer, AnnounceFixture::withHops($older['raw'], 0));
check('residual, stated and not closed: an older one makes a local destination on that row',
    localOf($db, $older['dest_hex']) === $claimer && !str_contains($log, '[ANNOUNCE-'), trim($log));
$expiring = RegFixture::identity();
$e1 = AnnounceFixture::announce($expiring, 'lxmf.delivery', 3, null, '', time() - 60);
feed($node, $gatewayRow, $e1['raw']);
$db->prepare('UPDATE path_entries SET expires_at = :t WHERE destination_hash_hex = :d')->execute([':t' => time() - 1, ':d' => $e1['dest_hex']]);
$e2 = AnnounceFixture::announce($expiring, 'lxmf.delivery', 0, null, '', time());
$expiringClaimer = legacyRow($node, browser($expiring['hash_hex']));
$log = feed($node, $expiringClaimer, $e2['raw']);
check('residual, stated: an expired path through the gateway no longer counts as held',
    localOf($db, $e1['dest_hex']) === $expiringClaimer && !str_contains($log, '[ANNOUNCE-'), trim($log));

echo "\n(8) maintenance keeps an announce's accepted copy, never a refused replay of it\n";
$keeper = RegFixture::identity();
$keeperRow = legacyRow($node, browser($keeper['hash_hex']));
$aK = AnnounceFixture::announce($keeper, 'lxmf.delivery', 0, null, 'k', time() - 30);
feed($node, $keeperRow, $aK['raw']);
// The same bytes again through the same row: §9 refuses the copy as seen. It
// ties with the accepted copy on hop count and interface, and is newer.
$log = feed($node, $keeperRow, $aK['raw']);
check('(precondition) the same announce again through the same row is refused as seen',
    str_contains($log, legacyRefusedLine($keeperRow, $aK['dest_hex'], 'seen')), trim($log));
$db->prepare('UPDATE inbound_packets SET created_at = created_at - 7200 WHERE packet_hash_hex = :h')->execute([':h' => $aK['packet_hash_hex']]);
$node->runMaintenance(300, 86400);
$left = q($db, 'SELECT announce_status FROM inbound_packets WHERE packet_hash_hex = :h', [':h' => $aK['packet_hash_hex']]);
check('past the inbound TTL one copy is left, and it is the accepted one',
    count($left) === 1 && in_array($left[0]['announce_status'], ['validated', 'path_updated'], true), json_encode($left));
check('...so a path or cache request can still be answered with it', $cachedAnnounce->invoke($node, $aK['packet_hash_hex']) !== null);

echo "\n(9) a cache request for a copy whose row §4.5 removed replays nothing\n";
if ($signedHere) {
    $retired = RegFixture::identity();
    $retiredRow = legacyRow($node, browser($retired['hash_hex']));
    $aR = AnnounceFixture::announce($retired, 'lxmf.delivery', 0, null, 'r', time() - 30);
    feed($node, $retiredRow, $aR['raw']);
    check("(precondition) the legacy row's own announce made its path and local destination there",
        (pathOf($db, $aR['dest_hex'])['interface_id'] ?? null) === $retiredRow && localOf($db, $aR['dest_hex']) === $retiredRow);
    $retiredSigned = (string) signedRow($node, $retired);
    $copies = q($db, 'SELECT interface_id FROM inbound_packets WHERE packet_hash_hex = :h', [':h' => $aR['packet_hash_hex']]);
    check('(precondition) the identity signs: §4.5 removes the legacy row, its path and its local destination, and its copy stays',
        $retiredSigned !== '' && q($db, 'SELECT 1 FROM interfaces WHERE interface_id = :i', [':i' => $retiredRow]) === []
        && pathOf($db, $aR['dest_hex']) === null && localOf($db, $aR['dest_hex']) === null
        && array_column($copies, 'interface_id') === [$retiredRow], json_encode($copies));
    check('that copy answers a cache request as not cached', $cacheRequestCopy->invoke($node, $aR['packet_hash_hex']) === null);
    check('...while the path request reader still finds it, as before', $cachedAnnounce->invoke($node, $aR['packet_hash_hex']) !== null);
    $knownR = knownOf($db, $aR['dest_hex']);
    $db->exec('DELETE FROM outbound_packets');
    $request = AnnounceFixture::cacheRequest($aR['packet_hash_hex']);
    $log = feed($node, $third, $request);
    check('a CACHE_REQUEST for it: miss (cached_announce_not_found)',
        verdictOf($db, AnnounceFixture::packetHash($request)) === ['miss', 'cached_announce_not_found'], json_encode(verdictOf($db, AnnounceFixture::packetHash($request))));
    check('...no announce is queued on any row', announcesQueued($db) === [], json_encode(announcesQueued($db)));
    check('...no path to the removed row, and known_destinations as it was',
        pathOf($db, $aR['dest_hex']) === null && q($db, 'SELECT 1 FROM path_entries WHERE interface_id = :i', [':i' => $retiredRow]) === []
        && knownOf($db, $aR['dest_hex']) === $knownR, trim($log));
}

echo "\n(10) a path request answered from a copy whose row §4.5 removed is answered as before\n";
if ($signedHere) {
    $mover = RegFixture::identity();
    $moverRow = legacyRow($node, browser($mover['hash_hex']));
    $aM = AnnounceFixture::announce($mover, 'lxmf.delivery', 0, null, 'm', time() - 30);
    feed($node, $moverRow, $aM['raw']);
    // The path through the legacy row lapses, and the same announce comes in
    // through the peer PHP node, two hops further out: the path moves there.
    $db->prepare('UPDATE path_entries SET expires_at = :t WHERE destination_hash_hex = :d')
        ->execute([':t' => time() - 1, ':d' => $aM['dest_hex']]);
    feed($node, $peerRow, AnnounceFixture::withHops($aM['raw'], 2));
    $moved = pathOf($db, $aM['dest_hex']);
    check('(precondition) the path moved to the peer PHP node, 3 hops, holding the same announce',
        ($moved['interface_id'] ?? null) === $peerRow && (int) ($moved['hops'] ?? -1) === 3
        && ($moved['packet_hash_hex'] ?? null) === $aM['packet_hash_hex'], json_encode($moved));
    // A link proof through the node then sets the path's hop count, as RNS
    // does (path_entry[IDX_PT_HOPS] = packet.hops: the rebalance in
    // request_relay_routing_trait.php), here to the legacy row's copy's 1.
    // Past the inbound TTL maintenance keeps the copy at the path's hop
    // count, the legacy row's, and deletes the peer's.
    $db->prepare('UPDATE path_entries SET hops = 1 WHERE destination_hash_hex = :d')->execute([':d' => $aM['dest_hex']]);
    $db->prepare('UPDATE inbound_packets SET created_at = created_at - 7200 WHERE packet_hash_hex = :h')->execute([':h' => $aM['packet_hash_hex']]);
    $node->runMaintenance(300, 86400);
    $kept = q($db, 'SELECT interface_id FROM inbound_packets WHERE packet_hash_hex = :h', [':h' => $aM['packet_hash_hex']]);
    check("(precondition) maintenance kept one copy, the legacy row's, while the path is through the peer PHP node",
        array_column($kept, 'interface_id') === [$moverRow] && (pathOf($db, $aM['dest_hex'])['interface_id'] ?? null) === $peerRow,
        json_encode([$kept, pathOf($db, $aM['dest_hex'])]));
    $before = pathAnswer($node, $db, $third, $aM['dest_hex']);
    check('(precondition) a path request is answered: one PATH_RESPONSE, for the row that asked',
        $before['verdict'] === ['response_queued', 'known_path_response'] && count($before['queued']) === 1
        && $before['queued'][0]['interface_id'] === $third && $before['queued'][0]['queue_reason'] === 'path_response',
        json_encode($before));
    // The identity signs: §4.5 removes the legacy row and keeps its copy.
    $pathM = pathOf($db, $aM['dest_hex']);
    $knownM = knownOf($db, $aM['dest_hex']);
    $moverSigned = (string) signedRow($node, $mover);
    $kept = q($db, 'SELECT interface_id FROM inbound_packets WHERE packet_hash_hex = :h', [':h' => $aM['packet_hash_hex']]);
    check("(precondition) the identity signs: §4.5 removes the legacy row, its copy stays the announce's only one, the path stands",
        $moverSigned !== '' && q($db, 'SELECT 1 FROM interfaces WHERE interface_id = :i', [':i' => $moverRow]) === []
        && array_column($kept, 'interface_id') === [$moverRow] && pathOf($db, $aM['dest_hex']) === $pathM, json_encode($kept));
    $after = pathAnswer($node, $db, $third, $aM['dest_hex']);
    check('a path request is answered exactly as before: the same verdict, the same PATH_RESPONSE bytes, for the same row, nothing else queued',
        $after === $before, json_encode(['before' => $before, 'after' => $after]));
    check('...and it changed no path and no known_destinations row',
        pathOf($db, $aM['dest_hex']) === $pathM && knownOf($db, $aM['dest_hex']) === $knownM);
    $db->exec('DELETE FROM outbound_packets');
    $request = AnnounceFixture::cacheRequest($aM['packet_hash_hex']);
    feed($node, $third, $request);
    check('a cache request for that copy is still a miss (cached_announce_not_found), and queues no announce',
        verdictOf($db, AnnounceFixture::packetHash($request)) === ['miss', 'cached_announce_not_found'] && announcesQueued($db) === [],
        json_encode([verdictOf($db, AnnounceFixture::packetHash($request)), announcesQueued($db)]));
}

echo "\n(11) a cache request whose copy's row goes before §9 reads it replays nothing\n";

/**
 * A request's connection to the node's SQLite file, set up as
 * Database::connect() sets one up, which runs $race once: after a cache
 * request has looked up its copy (cacheRequestCopySql(), which needs the
 * copy's row) and just before §9 reads that row (rowRegistrationFacts()), as
 * another request would in between.
 */
final class RowGoesPdo extends PDO
{
    /** @var (\Closure(): void)|null */
    public ?\Closure $race = null;
    public bool $raced = false;
    private bool $copyLookedUp = false;

    public function __construct(string $path)
    {
        parent::__construct('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $this->exec('PRAGMA busy_timeout = 5000');
        $this->exec('PRAGMA journal_mode = WAL');
        $this->exec('PRAGMA synchronous = NORMAL');
        $this->exec('PRAGMA foreign_keys = ON');
    }

    public function prepare(string $query, array $options = []): PDOStatement|false
    {
        $sql = (string) preg_replace('/\s+/', ' ', trim($query));
        if (str_contains($sql, 'FROM inbound_packets ip JOIN interfaces i ON i.interface_id = ip.interface_id')) {
            $this->copyLookedUp = true;
        } elseif ($this->copyLookedUp && $this->race !== null
            && str_starts_with($sql, 'SELECT registration_proof, metadata_json, identity_hash, claimed_identity_hash FROM interfaces')) {
            $race = $this->race;
            $this->race = null;
            $race();
            $this->raced = true;
        }

        return parent::prepare($query, $options);
    }
}

/**
 * A CACHE_REQUEST from $from for $packetHash, in a request of its own (a
 * Storage with an empty memo) during which $goes removes the copy's row
 * between the copy's lookup and §9's read of the row.
 */
function cacheRequestWhileRowGoes(string $dbPath, string $from, string $packetHash, \Closure $goes): array
{
    $request = RegFixture::storage([], $dbPath);
    $pdo = new RowGoesPdo($dbPath);
    (new ReflectionProperty(Storage::class, 'db'))->setValue($request, $pdo);
    $pdo->race = $goes;
    $cacheRequest = AnnounceFixture::cacheRequest($packetHash);
    $log = feed($request, $from, $cacheRequest);

    return ['log' => $log, 'raced' => $pdo->raced, 'request_hash' => AnnounceFixture::packetHash($cacheRequest)];
}

$gone = [];
if ($signedHere) {
    $leaver = RegFixture::identity();
    // The identity signs in another request: its bind's §4.5 removes the
    // legacy row claiming it, the row's path and local destination with it.
    $gone['a legacy row §4.5 removes'] = [$leaver, legacyRow($node, browser($leaver['hash_hex']), 'leaves'), 0,
        static function () use ($node, $leaver): void {
            signedRow($node, $leaver);
        }];
}
$carried = RegFixture::identity();
$deadPeerRow = legacyRow($node, RegFixture::phpPeerMetadata('https://dead-peer.example/reticulum'), 'dead peer PHP node');
// Another request's connectToPeer() removes the peering row as dead, with the
// statement it uses, before registering afresh.
$gone['a dead PHP node peering row, replaced'] = [$carried, $deadPeerRow, 1,
    static function () use ($db, $deadPeerRow): void {
        $db->prepare('DELETE FROM interfaces WHERE interface_id = :id')->execute([':id' => $deadPeerRow]);
    }];
foreach ($gone as $what => [$identity, $row, $hops, $goes]) {
    $a = AnnounceFixture::announce($identity, 'lxmf.delivery', $hops, null, 'goes', time() - 30);
    feed($node, $row, $a['raw']);
    check("[$what] (precondition) its announce made a path through the row",
        (pathOf($db, $a['dest_hex'])['interface_id'] ?? null) === $row, json_encode(pathOf($db, $a['dest_hex'])));
    if ($row === $deadPeerRow) {
        $db->exec('DELETE FROM outbound_packets');
        $request = AnnounceFixture::cacheRequest($a['packet_hash_hex']);
        feed(RegFixture::storage([], $dbPath), $third, $request);
        check("[$what] with the row there, a cache request for its copy is replayed as today",
            verdictOf($db, AnnounceFixture::packetHash($request))[0] === 'replayed'
            && in_array([$third, $a['packet_hash_hex']], announcesQueued($db), true),
            json_encode([verdictOf($db, AnnounceFixture::packetHash($request)), announcesQueued($db)]));
        // Then the row goes quiet, and the stale sweep removes its paths.
        $db->prepare('DELETE FROM path_entries WHERE interface_id = :i')->execute([':i' => $row]);
    }
    // known_destinations as if written a minute ago, so that a rewrite shows.
    $db->prepare('UPDATE known_destinations SET updated_at = updated_at - 60 WHERE destination_hash_hex = :d')
        ->execute([':d' => $a['dest_hex']]);
    $knownBefore = knownOf($db, $a['dest_hex']);
    $db->exec('DELETE FROM outbound_packets');
    $r = cacheRequestWhileRowGoes($dbPath, $third, $a['packet_hash_hex'], $goes);
    check("[$what] (precondition) the row went after the copy was looked up, before §9 read it",
        $r['raced'] && q($db, 'SELECT 1 FROM interfaces WHERE interface_id = :i', [':i' => $row]) === []);
    check("[$what] the replay is refused: [ANNOUNCE-FOREIGN] interface dest identity owner=none",
        str_contains($r['log'], foreignLine($row, $a['dest_hex'], $identity, 'none')), trim($r['log']));
    check("[$what] ...the cache request is a miss (cached_announce_not_relayed)",
        verdictOf($db, $r['request_hash']) === ['miss', 'cached_announce_not_relayed'], json_encode(verdictOf($db, $r['request_hash'])));
    check("[$what] ...no announce is queued on any row", announcesQueued($db) === [], json_encode(announcesQueued($db)));
    check("[$what] ...no path (none through the gone row), no local destination",
        pathOf($db, $a['dest_hex']) === null && q($db, 'SELECT 1 FROM path_entries WHERE interface_id = :i', [':i' => $row]) === []
        && localOf($db, $a['dest_hex']) === null, json_encode(pathOf($db, $a['dest_hex'])));
    check("[$what] ...and known_destinations as it was", knownOf($db, $a['dest_hex']) === $knownBefore,
        json_encode([$knownBefore, knownOf($db, $a['dest_hex'])]));
}

// A row that is there is read as before, in a later request of its own.
$later = RegFixture::storage([], $dbPath);
$db->exec('DELETE FROM outbound_packets');
$aGw = AnnounceFixture::announce(RegFixture::identity(), 'lxmf.delivery', 1);
$log = feed($later, $gatewayRow, $aGw['raw']);
check("a gateway row's announce is as today: a path through it, no local destination, forwarded, no [ANNOUNCE-] line",
    (pathOf($db, $aGw['dest_hex'])['interface_id'] ?? null) === $gatewayRow && localOf($db, $aGw['dest_hex']) === null
    && verdictOf($db, $aGw['packet_hash_hex'])[0] === 'path_updated'
    && in_array([$third, $aGw['packet_hash_hex']], announcesQueued($db), true) && !str_contains($log, '[ANNOUNCE-'), trim($log));
$legacyOwner = RegFixture::identity();
$browsers = ['a legacy browser row' => [$legacyOwner, legacyRow($node, browser($legacyOwner['hash_hex']))]];
if ($signedHere) {
    $signedOwner = RegFixture::identity();
    $browsers['a signed browser row'] = [$signedOwner, (string) signedRow($node, $signedOwner)];
}
foreach ($browsers as $what => [$identity, $row]) {
    $db->exec('DELETE FROM outbound_packets');
    $a = AnnounceFixture::announce($identity, 'lxmf.delivery', 0, null, 'own');
    $log = feed($later, $row, $a['raw']);
    check("$what's own announce is as today: its local destination, forwarded, no [ANNOUNCE-] line",
        localOf($db, $a['dest_hex']) === $row && in_array([$third, $a['packet_hash_hex']], announcesQueued($db), true)
        && !str_contains($log, '[ANNOUNCE-'), trim($log));
}

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
