<?php
// Test script to check configuration parsing

// Simulate the configuration
$wgDiscordRoleToGroupMapping = [
    '1128644540346142780' => 'orga',
    '1128545620513259550' => 'editor',
];

echo "Array keys:\n";
foreach ($wgDiscordRoleToGroupMapping as $key => $value) {
    echo "Key: " . var_export($key, true) . " (type: " . gettype($key) . ")\n";
    echo "Value: " . var_export($value, true) . "\n";
    echo "---\n";
}

echo "\nJSON encode/decode test:\n";
$json = json_encode($wgDiscordRoleToGroupMapping);
echo "JSON: " . $json . "\n";
$decoded = json_decode($json, true);
echo "After decode:\n";
foreach ($decoded as $key => $value) {
    echo "Key: " . var_export($key, true) . " (type: " . gettype($key) . ")\n";
    echo "Value: " . var_export($value, true) . "\n";
    echo "---\n";
}

echo "\nTest lookup:\n";
$testRole = '1128545620513259550';
echo "Looking for role: " . $testRole . "\n";
echo "isset check: " . (isset($wgDiscordRoleToGroupMapping[$testRole]) ? 'YES' : 'NO') . "\n";
if (isset($wgDiscordRoleToGroupMapping[$testRole])) {
    echo "Found: " . $wgDiscordRoleToGroupMapping[$testRole] . "\n";
}

echo "\nvar_dump of array:\n";
var_dump($wgDiscordRoleToGroupMapping);
