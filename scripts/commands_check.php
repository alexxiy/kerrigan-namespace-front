<?php declare(strict_types=1);

// The PHP half of commands.test.mjs, which runs it once per network: the front's signed commands
// through the indexer's own Protocol::parseCommand - the pre-check the registrar applies on
// arrival, and the full check against a name state the command is valid for - and the front's
// TXS/WDR signatures against the strings the registrar's API builds, with the expressions lifted
// from registrar-api/api/v1.0/transactions.php and balance.php. Also: the front's key derivation
// against libsodium, and each command against the 512-byte shielded memo.
//
//   NET=mainnet|testnet INDEXER=/path/to/kerrigan-name-indexer php scripts/commands_check.php vectors.json

const PROJECT_NAME = 'KNS';
define('COIN_NETWORK', getenv('NET'));
const PROTOCOL_MARKER = COIN_NETWORK === 'testnet' ? 't' . PROJECT_NAME : PROJECT_NAME;
const INT_EXC_DB = 1;
const KERRIGAN_MEMO_MAX_BYTES = 512;

if (!in_array(COIN_NETWORK, ['mainnet', 'testnet'], true) || !isset($argv[1])) {
    fwrite(STDERR, 'Usage: NET=mainnet|testnet INDEXER=/path/to/kerrigan-name-indexer php commands_check.php vectors.json' . PHP_EOL);
    exit(2);
}
$indexer = getenv('INDEXER');
require $indexer . '/vendor/autoload.php';
require $indexer . '/include/Protocol.php';

// The name state parseCommand reads, set by the test instead of the database.
final class P extends \Indexer\Protocol
{
    public static function seed(string $domain, array|false $state): void
    {
        self::$domainsCache = [$domain => $state];
        self::clearDomainState();
    }
}

// The registrar's signed strings, as its API builds them: the expression itself, lifted by pattern,
// so a change there is tested here.
$lift = static function (string $file, string $pattern): string {
    if (preg_match($pattern, (string)file_get_contents($file), $m) !== 1) {
        throw new RuntimeException("The signed string was not found in $file - did it change?");
    }
    return $m[1];
};
$registrarApi = $indexer . '/registrar-api/api/v1.0';
$signedExpr = [
    'TXS' => $lift($registrarApi . '/transactions.php', "/^\\\$signed = (PROTOCOL_MARKER \\. ':1:TXS:'[^;\\n]*);\$/m"),
    'WDR' => $lift($registrarApi . '/balance.php', "/^\\s*(PROTOCOL_MARKER \\. ':1:WDR:'[^,\\n]*),\$/m"),
];
$registrarSigned = static function (string $kind, array $vars) use ($signedExpr): string {
    extract($vars);
    return eval('return ' . $signedExpr[$kind] . ';');
};

$v = json_decode((string)file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR);
$pass = 0;
$fail = 0;
$check = static function (string $name, bool $ok) use (&$pass, &$fail): void {
    if ($ok) {
        $pass++;
    } else {
        $fail++;
        echo "  FAIL  $name\n";
    }
};

foreach ($v['keys'] as $k) {
    $kp = sodium_crypto_sign_seed_keypair(hash('sha256', $k['phrase'], true));
    $check('key: SHA-256 of the phrase as the Ed25519 seed gives the front\'s public key',
        bin2hex(sodium_crypto_sign_publickey($kp)) === $k['pub']);
}
[$pubA, $pubB] = [$v['keys'][0]['pub'], $v['keys'][1]['pub']];

$nonce = 1780000000;
$cases = 0;
foreach ($v['cases'] as $c) {
    if ($c['net'] !== COIN_NETWORK) {
        continue;
    }
    $cases++;
    $parts = explode(':', $c['memo']);
    $domain = $parts[3];
    $check("{$c['name']}: fits the shielded memo (" . strlen($c['memo']) . ' bytes)', strlen($c['memo']) <= KERRIGAN_MEMO_MAX_BYTES);

    // The pre-check: what the registrar applies when a payment arrives.
    P::seed($domain, false);
    $check("{$c['name']}: pre-check", P::parseCommand($c['memo'], 1, $nonce, true) !== []);

    // The full check, against a state the command is valid for. A REG's adds only the state: that
    // the name is free, and that no other name holds its tree path (Protocol::pathTaken(), which
    // reads the indexer's database; its resources/tests/protocol_test.php covers that). So a REG
    // is held to the pre-check, which takes its format and its signature as the full check does.
    $preOnly = $c['op'] === 'REG';
    $other = COIN_NETWORK === 'testnet'
        ? 'ktestsapling197dutnjl4e58a6ayshfhk9wu5edr7h90m4jtp27cd3ysqc2dsglph64vtmqm5sm27dgwv6mhr2t'
        : 'ks14ge6h7x58v3le8zyrvxejha5gkvqvwy9emt23sudwxe5up44flxww0vuzv0rwgrqcd5m2mjtg44';
    $owned = ['target_address' => $other, 'owner_pubkey' => $pubA, 'nonce' => $nonce - 10, 'price' => 0];
    [$state, $amount] = match ($c['op']) {
        'REG' => [false, P::getDomainPrice($domain, 'REG')],
        'BUY' => [['owner_pubkey' => $pubB, 'price' => 777] + $owned, 777],
        'UPD' => [$owned, P::getDomainPrice($domain, 'UPD')],
        'CHG', 'LST' => [$owned, P::getDomainPrice($domain, $c['op'])],
        'ULT' => [['price' => 5] + $owned, P::getDomainPrice($domain, 'ULT')],
    };
    P::seed($domain, $state);
    $cmd = P::parseCommand($c['memo'], $amount, $nonce, $preOnly);
    $check("{$c['name']}: " . ($preOnly ? 'format and signature' : 'full check'), $cmd !== []);
    if ($cmd !== []) {
        $check("{$c['name']}: payment amount valid", P::paymentAmountValid($cmd, $amount));
        if ($c['op'] === 'LST') {
            $check("{$c['name']}: price parsed exactly", $cmd['price'] === (int)$parts[5]);
        }
        if ($c['op'] === 'CHG') {
            $check("{$c['name']}: new owner taken", $cmd['pubkey'] === $pubB);
        }
    }

    // The same memo with one signature digit changed, or the signature in upper case, is refused.
    $sig = end($parts);
    $flip = substr($c['memo'], 0, -1) . (str_ends_with($sig, '0') ? '1' : '0');
    P::seed($domain, $state);
    $check("{$c['name']}: altered signature refused", P::parseCommand($flip, $amount, $nonce, $preOnly) === []);
    P::seed($domain, $state);
    $upper = substr($c['memo'], 0, -128) . strtoupper($sig);
    $check("{$c['name']}: upper-case signature refused", P::parseCommand($upper, $amount, $nonce, $preOnly) === []);
    // A command signed for the other network is refused here.
    $otherMarker = COIN_NETWORK === 'testnet' ? 'KNS' : 'tKNS';
    P::seed($domain, $state);
    $check("{$c['name']}: the other network's marker refused",
        P::parseCommand($otherMarker . substr($c['memo'], strlen(PROTOCOL_MARKER)), $amount, $nonce, $preOnly) === []);
}
$check('commands of this network were given', $cases > 0);

$requests = 0;
foreach ($v['requests'] as $r) {
    if ($r['net'] !== COIN_NETWORK) {
        continue;
    }
    $requests++;
    $f = $r['fields'];
    // The values as the registrar holds them when it builds the string: the WDR amount comes as a
    // digit string and is taken as an integer (balance.php).
    $vars = match ($r['kind']) {
        'TXS' => ['type' => $f['type'], 'pubkey' => $f['pubkey'], 'page' => $f['page'], 'count' => $f['count'], 'nonce' => $f['nonce']],
        'WDR' => ['pubkey' => $f['pubkey'], 'address' => $f['address'], 'amount' => (int)$f['amount'], 'nonce' => $f['nonce']],
    };
    $signed = $registrarSigned($r['kind'], $vars);
    $check("{$r['kind']} {$signed}: verifies as the registrar builds it",
        sodium_crypto_sign_verify_detached(hex2bin($r['signature']), $signed, hex2bin($f['pubkey'])));
    if ($r['kind'] === 'WDR') {
        // balance.php takes a digit string by this pattern, and signs the integer it reads.
        $check("WDR amount {$f['amount']}: a digit string balance.php takes",
            preg_match('/^[1-9][0-9]{0,17}$/D', $f['amount']) === 1 && (string)(int)$f['amount'] === $f['amount']);
    }
}
$check('requests of this network were given', $requests > 0);

echo COIN_NETWORK . ": $pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
