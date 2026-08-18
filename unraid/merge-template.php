#!/usr/bin/php
<?php
/**
 * Merge new Unraid Docker template Config entries into an existing user template
 * without wiping passwords, webhooks, or custom host paths.
 *
 * Usage: php merge-template.php EXISTING.xml FRESH.xml
 */
if ($argc < 3) {
    fwrite(STDERR, "usage: merge-template.php EXISTING.xml FRESH.xml\n");
    exit(1);
}

$existingPath = $argv[1];
$freshPath = $argv[2];

if (!is_file($freshPath)) {
    fwrite(STDERR, "fresh template missing: {$freshPath}\n");
    exit(1);
}

if (!is_file($existingPath)) {
    if (!copy($freshPath, $existingPath)) {
        fwrite(STDERR, "copy failed\n");
        exit(1);
    }
    echo "installed new template\n";
    exit(0);
}

$old = simplexml_load_file($existingPath);
$new = simplexml_load_file($freshPath);
if ($old === false || $new === false) {
    fwrite(STDERR, "XML parse failed\n");
    exit(1);
}

function cfg_name(SimpleXMLElement $c): string
{
    return strtolower(trim((string) $c['Name']));
}

function cfg_target(SimpleXMLElement $c): string
{
    return trim((string) $c['Target']);
}

function cfg_value(SimpleXMLElement $c): string
{
    return trim((string) $c);
}

function set_cfg_value(SimpleXMLElement $c, string $value): void
{
    $dom = dom_import_simplexml($c);
    while ($dom->firstChild) {
        $dom->removeChild($dom->firstChild);
    }
    if ($value !== '') {
        $dom->appendChild($dom->ownerDocument->createTextNode($value));
    }
}

$upgraded = [];
foreach ($old->Config as $c) {
    $name = cfg_name($c);
    $target = cfg_target($c);
    if ($name === 'crowdsec bouncer yaml' || $target === '/crowdsec-bouncer/config.yaml') {
        $host = cfg_value($c);
        if ($host !== '' && preg_match('#/config\\.ya?ml$#i', $host)) {
            $host = dirname($host);
        }
        if ($host === '' || $host === '.' || $host === '/') {
            $host = '/mnt/user/appdata/zoraxy/plugin/zoraxy_crowdsec_bouncer';
        }
        $c['Name'] = 'CrowdSec Bouncer';
        $c['Target'] = '/crowdsec-bouncer';
        $c['Default'] = '/mnt/user/appdata/zoraxy/plugin/zoraxy_crowdsec_bouncer';
        $c['Description'] = 'Zoraxy CrowdSec-Plugin-Ordner mit config.yaml (nicht die Datei allein). Alternativ .../plugins/zoraxy_crowdsec_bouncer';
        $c['Type'] = 'Path';
        $c['Mode'] = 'rw';
        set_cfg_value($c, $host);
        $upgraded[] = 'CrowdSec Bouncer (Ordner statt Datei)';
    }
}

$byName = [];
$byTarget = [];
foreach ($old->Config as $c) {
    $byName[cfg_name($c)] = $c;
    $t = cfg_target($c);
    if ($t !== '') {
        $byTarget[$t] = $c;
    }
}

$added = [];
$filled = [];

foreach ($new->Config as $c) {
    $name = cfg_name($c);
    $target = cfg_target($c);
    $newVal = cfg_value($c);
    if ($newVal === '') {
        $newVal = trim((string) $c['Default']);
    }

    $hit = $byName[$name] ?? null;
    if ($hit === null && $target !== '' && isset($byTarget[$target])) {
        $hit = $byTarget[$target];
    }

    if ($hit !== null) {
        if (cfg_value($hit) === '' && $newVal !== '') {
            set_cfg_value($hit, $newVal);
            $filled[] = (string) $c['Name'];
        }
        continue;
    }

    $node = $old->addChild('Config');
    set_cfg_value($node, $newVal);
    foreach ($c->attributes() as $k => $v) {
        $node->addAttribute($k, (string) $v);
    }
    $added[] = (string) $c['Name'];
}

$tmp = $existingPath . '.tmp';
if ($old->asXML($tmp) === false || !rename($tmp, $existingPath)) {
    fwrite(STDERR, "write failed\n");
    exit(1);
}

$parts = [];
if ($upgraded) {
    $parts[] = 'angepasst: ' . implode(', ', $upgraded);
}
if ($added) {
    $parts[] = 'neu: ' . implode(', ', $added);
}
if ($filled) {
    $parts[] = 'leer ergänzt: ' . implode(', ', $filled);
}
echo $parts ? implode('; ', $parts) . "\n" : "template already complete\n";
