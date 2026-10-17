<?php
/**
 * A path request's tag is remembered under a key that fits its column.
 *
 * path_request_tags.tag_key_hex is VARCHAR(32). Until 2026-10-16 the key was
 * the destination hash and the tag in hex, 64 characters; MySQL's INSERT
 * IGNORE cut it to 32, the destination hash alone, so on retichat.com (MySQL)
 * one browser's path request made every other request for that destination,
 * whatever its tag, a "duplicate_path_request_tag" for 24 h. Private staging
 * on MySQL showed it 2026-10-16: the second browser never learned rfed's
 * propagation node and parked its message. SQLite keeps the whole string, so
 * the SQLite suite never saw it; this test checks what MySQL would keep.
 *
 * Against the real Storage (SQLite):
 *   (1) the key fits the column the schema declares, so MySQL keeps all of it
 *   (2) two tags for one destination, and one tag for two destinations, give
 *       keys that differ in what MySQL keeps
 *   (3) rememberPathRequestTag(): a tag is remembered once; another tag for
 *       the same destination is a new request; the stored key is whole
 *
 * Run: php php/tests/path_request_tag_key_test.php
 */
declare(strict_types=1);

namespace ReticulumPhp;

require_once dirname(__DIR__) . '/src/index.php';
require_once __DIR__ . '/stubs/registration_fixture.php';

use PDO;
use RegFixture;

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

$storage = new Storage(RegFixture::config());
$storage->migrateIfNeeded();
$key = \Closure::bind(static fn (string $dest, string $tag): string => Storage::pathRequestTagKey($dest, $tag), null, Storage::class);
$remember = \Closure::bind(fn (string $k): bool => $this->rememberPathRequestTag($k), $storage, Storage::class);

echo "\n(1) the key fits the column the schema declares\n";
$schema = (string) file_get_contents(dirname(__DIR__) . '/src/lib/request_schema_trait.php');
$declared = preg_match('/tag_key_hex\s+VARCHAR\((\d+)\)/', $schema, $m) === 1 ? (int) $m[1] : 0;
check('the schema declares tag_key_hex VARCHAR(n)', $declared > 0);
$dest = str_repeat('ab', 16);
$otherDest = str_repeat('cd', 16);
$tagA = random_bytes(16);
$tagB = random_bytes(16);
$k = $key($dest, $tagA);
check("the key is at most $declared characters, so MySQL keeps all of it", strlen($k) <= $declared, strlen($k) . ' characters');
check('the key is hex', ctype_xdigit($k));
check('the key is the same for the same destination and tag', $k === $key($dest, $tagA));

echo "\n(2) different requests differ in what MySQL keeps\n";
$kept = static fn (string $k): string => substr($k, 0, $declared);
check('two tags for one destination', $kept($key($dest, $tagA)) !== $kept($key($dest, $tagB)));
check('one tag for two destinations', $kept($key($dest, $tagA)) !== $kept($key($otherDest, $tagA)));
check('a tag shorter than 16 bytes (as Python allows)', $kept($key($dest, 'short')) !== $kept($key($dest, 'shorter')));

echo "\n(3) rememberPathRequestTag()\n";
check('a first request is remembered', $remember($key($dest, $tagA)) === true);
check('the same destination and tag again is a duplicate', $remember($key($dest, $tagA)) === false);
check('another tag for the same destination is a new request', $remember($key($dest, $tagB)) === true);
check('the same tag for another destination is a new request', $remember($key($otherDest, $tagA)) === true);
$longest = (int) RegFixture::db($storage)->query('SELECT MAX(LENGTH(tag_key_hex)) FROM path_request_tags')->fetchColumn();
check("every stored key is at most $declared characters", $longest > 0 && $longest <= $declared, (string) $longest);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
