<?php

$keys = "";

function readKeys(string $path, string &$keys): bool
{
    $handle = fopen($path, "rb");
    if ($handle === false) {
        printf("Failed to open keys file");
        return false;
    }
    $keys = fread($handle, filesize($path));
    fclose($handle);
    return true;
}

function readDataFile(string $path, string &$buffer, int &$fileSize): bool
{
    $handle = fopen($path, "rb");
    if ($handle === false) {
        printf("Failed to open data file");
        return false;
    }
    $fileSize = filesize($path);
    $buffer = fread($handle, $fileSize);
    fclose($handle);
    return true;
}

function encrypt(string &$decryptedFileRaw, int $length, string $keys): void
{
    for ($off = 0; $off < $length;) {
        $packetLength = unpack("S", $decryptedFileRaw, $off)[1];
        $key = unpack("C", $decryptedFileRaw, $off + 2)[1];
        $key = unpack("C", $keys, ($key << 1) % 512)[1];
        for ($i = $off + 4; $i < $off + $packetLength; $i++) {
            $mappedKey = unpack("C", $keys, (($key % 256) << 1) % 512 + 1)[1];
            $currValue = unpack("C", $decryptedFileRaw, $i)[1];
            switch ($i & 3) {
                case 0:
                    $currValue = ($currValue + ($mappedKey << 1)) & 255;
                    break;
                case 1:
                    $currValue = ($currValue - ($mappedKey >> 3)) & 255;
                    break;
                case 2:
                    $currValue = ($currValue + ($mappedKey << 2)) & 255;
                    break;
                case 3:
                    $currValue = ($currValue - ($mappedKey >> 5)) & 255;
                    break;
            }
            $decryptedFileRaw[$i] = pack("C", $currValue);
            $key++;
        }
        $off += $packetLength;
    }
}

function decrypt(string &$encryptedFileRaw, int $length, string $keys): void
{
    for ($off = 0; $off < $length;) {
        $packetLength = unpack("S", $encryptedFileRaw, $off)[1];
        $key = unpack("C", $encryptedFileRaw, $off + 2)[1];
        $key = unpack("C", $keys, $key << 1)[1];
        for ($i = $off + 4; $i < $off + $packetLength; $i++) {
            $mappedKey = unpack("C", $keys, (($key % 256) << 1) % 512 + 1)[1];
            $currValue = unpack("C", $encryptedFileRaw, $i)[1];
            switch ($i & 3) {
                case 0:
                    $currValue = ($currValue - ($mappedKey << 1)) & 255;
                    break;
                case 1:
                    $currValue = ($currValue + ($mappedKey >> 3)) & 255;
                    break;
                case 2:
                    $currValue = ($currValue - ($mappedKey << 2)) & 255;
                    break;
                case 3:
                    $currValue = ($currValue + ($mappedKey >> 5)) & 255;
                    break;
            }
            $encryptedFileRaw[$i] = pack("C", $currValue);
            $key++;
        }
        $off += $packetLength;
    }
}

if ($argc < 5) {
    exit(-1);
}
if (readKeys($argv[1], $keys) === false) {
    exit(-2);
}
$encryptedFileRaw = "";
$encryptedFileRawSize = 0;
if (readDataFile($argv[3], $encryptedFileRaw, $encryptedFileRawSize) === false) {
    exit(-3);
}
$decryptedFileRaw = "";
$decryptedFileRawSize = 0;
if (readDataFile($argv[4], $decryptedFileRaw, $decryptedFileRawSize) === false) {
    exit(-4);
}
$op = $argv[2];
if ($op === "enc") {
    encrypt($decryptedFileRaw, $decryptedFileRawSize, $keys);
    $out = fopen("./encoded.bin", "wb");
    fwrite($out, $decryptedFileRaw);
    fclose($out);
}
if ($op === "dec") {
    decrypt($encryptedFileRaw, $encryptedFileRawSize, $keys);
    $out = fopen("./decoded.bin", "wb");
    fwrite($out, $encryptedFileRaw);
    fclose($out);
}
$diff = 0;
for ($i = 0; $i < $encryptedFileRawSize; $i++) {
    $diff += ($encryptedFileRaw[$i] !== $decryptedFileRaw[$i]);
}
printf("%d differences", $diff);
