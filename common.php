<?php

/**
 * Extract the domain name and TLD from a fully qualified domain name (FQDN).
 *
 * @param string $fqdn The fully qualified domain name.
 * @return string The domain name and TLD (e.g., "example.com").
 */
function get_domain($fqdn) {
    // Use PHP's parse_url to extract the host part if a URL is passed
    $fqdn = parse_url($fqdn, PHP_URL_HOST) ?: $fqdn;

    // Split the FQDN into parts
    $parts = explode('.', $fqdn);

    // If there are fewer than 2 parts, it is not a valid domain name
    if (count($parts) < 2) {
        return $fqdn; // Return as is (could be an IP or local name)
    }

    // Return the last two parts (domain and TLD)
    return implode('.', array_slice($parts, -2));
}


/**
 * Set a specific bit in a binary string.
 *
 * @param string $bits   The binary string (36 bytes).
 * @param int    $bucket The bucket index to set.
 * @return string The modified binary string.
 */
function setBit(string $bits, int $bucket): string {
    $byteIndex = intdiv($bucket, 8);
    $bitIndex = $bucket % 8;

    
    $byte = ord($bits[$byteIndex]);
    $byte |= (1 << $bitIndex);
    echo " =-= $bucket ($byteIndex / $bitIndex) = 0x" . dechex($byte) . "\n";
    $bits[$byteIndex] = chr($byte);
    return $bits;
}

/**
 * Unset a specific bit in a binary string.
 *
 * @param string $bits   The binary string (36 bytes).
 * @param int    $bucket The bucket index to unset.
 * @return string The modified binary string.
 */
function unsetBit(string $bits, int $bucket): string {
    $byteIndex = intdiv($bucket, 8);
    $bitIndex = $bucket % 8;
    
    $byte = ord($bits[$byteIndex]);
    $byte &= ~(1 << $bitIndex);
    $bits[$byteIndex] = chr($byte);
    return $bits;
}

/**
 * Clear all bits in a range [start, end] inclusive, handling empty or invalid ranges gracefully.
 *
 * @param string $bits  The binary string.
 * @param int    $start Start bucket index.
 * @param int    $end   End bucket index.
 * @return string The modified binary string.
 */
function clearRange(string $bits, int $start, int $end): string {
    if ($start > $end) {
        return $bits; // No range to clear
    }
    for ($b = $start; $b <= $end; $b++) {
        $bits = unsetBit($bits, $b);
    }
    return $bits;
}


/**
 * TODO: expire mac addresses out of IP address after 1 day
 * get the ethernet address associated with an ip address
 */
function get_ethernet(string $ip_address): ?string {
    // Execute the 'arp' command
    $output = shell_exec("ip neigh show $ip_address 2>/dev/null");

    // Check if output contains a valid MAC address
    if (preg_match('/(?:[0-9a-f]{2}:){5}[0-9a-f]{2}/i', $output, $matches)) {
        return strtoupper($matches[0]); // Return the MAC address
    }
    echo "## ERR: [$output]\n";

    return null; // MAC address not found
}


/**
 * take a file with a list of entries as return a map with each row as a key and row number as value
 */
function file_keys(string $filename) : array {
    $result = [];
    $x = fopen($filename, "r");
    $ctr = 1;
    while ($line = fgets($x)) {
        $result[trim($line)] = $ctr++;
    }
    return $result;
}
