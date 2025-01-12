<?php
use function ThreadFin\HTTP\http2;

/**
 * utility functions.  tests are in tests/test_common.php
 * run tests as: php tinytest/tinytest.php -d tests
 */

/**
 * Get the bucket index (0-287) corresponding to a given DateTime.
 *
 * @param DateTime $dt The date-time object.
 * @return int Bucket index (0 to 2009). - return 2010 if $dt was null
 */
function get_bucket_index(?DateTime $dt): int {
    if ($dt == null) {
        return 2010;
    }
    $seconds_since_midnight = ($dt->format('H') * 3600) + ($dt->format('i') * 60) + $dt->format('s');
    $day_offset = $dt->format('w') * 36;
    $result = intdiv($day_offset + $seconds_since_midnight, 300); // 300s = 5min
    ASSERT($result >= 0 && $result <= 2009, "ERR: edge bucket calculation incorrect, got [$result]");
    return $result;
}


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

function checkBit($bits, int $bucket): bool {
    $byteIndex = intdiv($bucket, 8);
    $bitIndex = $bucket % 8;

    
    $byte = ord($bits[$byteIndex]);
    return ($byte & (1 << $bitIndex));
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
 * take a file with a list of entries as return a map with each row as a key
 * and row number as value
 */
function file_keys(string $filename) : array {
    $result = [];
    if (file_exists($filename)) {
        $x = fopen($filename, "r");
        $ctr = 1;
        while ($line = fgets($x)) {
            $parts = explode(',', strtolower(trim($line)));
            foreach ($parts as $element) {
                $result[trim($element)] = $ctr;
            }
            $ctr++;
        }
        fclose($x);
    }
    return $result;
}

/**
 * return the category id from malware/categories.txt of $value.
 * uses line number in categories.txt as cat_id. falls back to $cat_id if no match
 */
function get_category_id($value, $cat_id) {
    static $list = NULL; 
    static $age = -1; 
    if ($list == NULL || filemtime("malware/categories.txt") > $age) {
        $list = file_keys("malware/categories.txt");
        $age = time();
        gc_collect_cycles();
    }
    $check = trim(str_ireplace("(alphamountain.ai)", "", strtolower($value)));
    if (!isset($list[$check])) {
        $list[$check] = count($list) + 1;
        echo " ++ add category ($check)\n";
        file_put_contents("malware/categories.txt", join("\n", array_keys($list)), LOCK_EX);
    }

    return $list[$check] ?? $cat_id;
}

/**
 * query google safe browsing for $domain and return true if a hit was found
 * TODO: parse the response. just returns hit currently...
 */
function google_safe_browsing(string $domain, array $config) : bool {

    // make sure we have an API key...
    if (!isset($config['safebrowsing_api']) || empty($config['safebrowsing_api'])) {
        return false;
    }

    $query = '{
        "client": {
        "clientId": "bitslip6",
        "clientVersion": "1.0.0"
        },
        "threatInfo": {
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        "platformTypes":    ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL", "EXECUTABLE"],
        "threatEntries": [
            {"url": "http://'.$domain.'/"},
            {"url": "https://'.$domain.'/"}
        ]
        }
    }';
    //{"url": "https://testsafebrowsing.appspot.com/s/phishing.html"}

    $d = json_decode($query, true);
    $e = json_encode($d);

    $r = http2("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" . $config['safebrowsing_api']??'', $e, ['Content-Type' => 'application/json']);
    return ($r->len < 10);

/*
{
    $response = json_decode($r->content);
    "matches": [
      {
        "threatType": "SOCIAL_ENGINEERING",
        "platformType": "WINDOWS",
        "threat": {
          "url": "https://testsafebrowsing.appspot.com/s/phishing.html"
        },
        "cacheDuration": "300s",
        "threatEntryType": "URL"
      }
    ]
  }
    */

}


// return true if attack_info['id'] is not one of DISABLED_MITRE
function alien_attack_id_filter(array $attack_info) : bool {
    return ! in_array($attack_info['id'], DISABLED_MITRE);
}




/**
 * todo rewrite with http2. convert this to a score metric, and category
 * location redirects
 */
function fetch_details($domain) {
    $url = "https://{$domain}/";
    $r = http2("GET", $url);
    /*
    $ch = curl_init($url);

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // We'll manually check for redirects
    curl_setopt($ch, CURLOPT_CERTINFO, true);
    curl_setopt($ch, CURLOPT_HEADER, true);

    $response = curl_exec($ch);
    $info = curl_getinfo($ch);
    $certinfo = curl_getinfo($ch, CURLINFO_CERTINFO);

    if ($response === false) {
        echo "cURL Error: " . curl_error($ch) . "\n";
    }

    curl_close($ch);

    // Separate headers and body
    $header_size = $info['header_size'];
    $headers_str = substr($response, 0, $header_size);
    $html = substr($response, $header_size);
    */

    // Extract final location if there's a redirect
    $final_url = $url;
    if (preg_match('/Location:\s*(.*)/i', $headers_str, $m)) {
        $redirect_location = trim($m[1]);
        $final_url = $redirect_location;
    }

    // Parse title
    $title = "";
    if (preg_match("/<title>(.*?)<\/title>/is", $html, $matches)) {
        $title = trim($matches[1]);
    }

    // Parse meta description
    $description = "";
    if (preg_match('/<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']/is', $html, $matches)) {
        $description = trim($matches[1]);
    }

    // Check for offsite HTML redirects
    $offsite_redirect = "";
    if (preg_match('/<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"]*url=([^"\' ]+)/i', $html, $matches)) {
        $offsite_redirect = $matches[1];
    }

    // Simple check for obfuscated scripts
    /*
    $obfuscated_scripts = false;
    $patterns = array(
        '/<script[^>]*>[^<]*base64[^<]*<\/script>/i',
        '/<script[^>]*>.*eval\(.*\).*<\/script>/is',
        '/<script[^>]*>.*document\.location[^<]*<\/script>/is'
    );
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $html)) {
            $obfuscated_scripts = true;
            break;
        }
    }

    // Certificate details (from CURLINFO_CERTINFO)
    // This is an array of certificates in the chain. Index 0 is the server cert.
    // Format can vary depending on Curl/Libcurl version.
    $cert_details = array();
    if (is_array($certinfo) && count($certinfo) > 0) {
        foreach ($certinfo as $cert) {
            // Not all fields may be available; adjust parsing as needed.
            // Typically, $cert will contain fields like 'Subject', 'Issuer', etc.
            $cert_details[] = $cert;
        }
    }
        */

    // Determine hosting provider by whois on IP address
    $ip = gethostbyname($domain);
    $whois_data = shell_exec("whois " . escapeshellarg($ip));
    $hosting_provider = extract_hosting_provider($whois_data);

    return array(
        'final_url' => $final_url,
        'title' => $title,
        'description' => $description,
        'offsite_redirect' => $offsite_redirect,
        'obfuscated_scripts' => $obfuscated_scripts,
        'cert_details' => $cert_details,
        'ip' => $ip,
        'hosting_provider' => $hosting_provider
    );
}



function extract_hosting_provider($whois_data) {
    // This is a heuristic approach. Different RIRs (ARIN, RIPE, APNIC) have different formats.
    // Common fields might include "OrgName", "Organization", "owner", "descr".
    // We'll try a few patterns:
    $patterns = array(
        '/OrgName:\s+(.*)/i',
        '/Organization:\s+(.*)/i',
        '/descr:\s+(.*)/i'
    );
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $whois_data, $matches)) {
            return trim($matches[1]);
        }
    }
    return "Unknown Hosting Provider";
}