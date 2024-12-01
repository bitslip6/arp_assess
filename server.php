<?php

use ThreadFin\DB\DB;

require "threadfin/db.php";


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


function get_txt_records($domain) {
    // Perform a DNS query for TXT records
    $records = dns_get_record($domain, DNS_TXT);

    // Extract the TXT entries
    $txtRecords = [];
    foreach ($records as $record) {
        if (isset($record['txt'])) {
            $txtRecords[] = $record['txt'];
        }
    }

    return $txtRecords;
}


class Whois_Info {
    public string $city = "";
    public int $zip = 0;
    public string $country = "";
    public string $as = "";
    public string $org = "";
    public string $arin = "";
    public string $cidr = "";
    public string $net = "";
    public string $raw = "";
    public string $created = "";
    public string $expires = "";
    public string $registrar = "";
    public array $domains = [];

    public function __toString()
    {
        return (!empty($this->raw)) 
            ? $this->raw
            : "Whois_Info: $this->as $this->org $this->country $this->cidr $this->net"; 
    }
}


/**
 * @param resource $stream - stream to read
 * @param int $size - read block size
 * @return string - the entire stream as a string
 */
function read_stream($stream, $size=8192) {
    $data = "";
    if(!empty($stream)) {
        while (!feof($stream)) {
            $data .= fread($stream , $size);
        }
        fclose ($stream);
    }
    return $data;
}


/**
 * find the AS number of the remote IP
 * TODO: add remote classifier hosted on bitfire.co for difficult to classify IPs
 * @param string $remote_ip 
 * @return Whois_Info the AS number as a string or empty string
 */
function find_whois(string $remote_ip, bool $return_raw = false): Whois_Info
{
    static $cache = [];
    static $whois_servers = [
        'whois.ripe.net' => 'RIPE',
        'whois.arin.net' => 'ARIN',
        'whois.apnic.net' => 'APNIC',
        'whois.afrinic.net' => 'AFRINIC',
        'whois.lacnic.net' => 'LACNIC'
    ];

    // this is an expensive call, make sure we don't accidentally do it twice
    if (isset($cache[$remote_ip])) {
        return $cache[$remote_ip];
    }

    $info = new Whois_Info();

    foreach ($whois_servers as $server => $org) {
        $write_ip_fn = ƒixr('fputs', "$remote_ip\r\n");
        $x = MaybeStr::of(fsockopen($server, 43, $no, $str, 1))
            ->effect($write_ip_fn)
            ->then('read_stream');
        $info->raw = ($return_raw) ? "" : $x;

        //  pull the as number from anywhere
        if (preg_match("/AS([0-9]+)/", $x, $matches)) {
            $info->as = $matches[1];
        }
        // city is common
        if (preg_match("/city[^:]*:\s*(.*)/i", $x, $matches)) {
            $info->city = $matches[1];
        }
        // created date
        if (preg_match("/creat[^:]*:\s*(.*)/i", $x, $matches)) {
            $info->created = $matches[1];
        }
        // expired date
        if (preg_match("/expir[^:]*:\s*(.*)/i", $x, $matches)) {
            $info->expires = $matches[1];
        }
        // registrar date
        if (preg_match("/registrar:\s*(.*)/i", $x, $matches)) {
            $info->registrar = $matches[1];
        }
        // so is country
        if (preg_match("/country[^:]*:\s*(.*)/i", $x, $matches)) {
            $info->country = icontains($matches[1], "world")  ? "global" : $matches[1];
        }
        // postal is sometimes in an address field
        if (preg_match("/postalcode[^:]*:\s*(.*)/i", $x, $matches)) {
            $info->zip = $matches[1];
        }
        if (empty($info->zip) && preg_match("/address:[^:]*:.*?(\d{5})/i", $x, $matches)) {
            $info->zip = $matches[1];
        }
        // pull cidr from anywhere
        if (empty($info->cidr) && preg_match("/([0-9.:]+\/\d+)/i", $x, $matches)) {
            $info->cidr = $matches[1];
        }

        // pull the net range
        if (preg_match("/([\d.:]+\s+-\s+[\d.:]+)/i", $x, $matches)) {
            $info->net = $matches[1];
        }

        // pull the org name from likely places
        if (preg_match("/(org|descr|owner|netname)[^:]*:+\s*(.*)/i", $x, $matches)) {
            $info->org .= $matches[1] . "\n";
        }
        // pull all email addresses
        if (preg_match("/[\w_\.-]+\@(\w+\.\w+)/i", $x, $matches)) {
            $info->domains[] = $matches[1];
        }

        if (!empty($info->as) || !empty($info->org) || !empty($info->country)) {
            $info->arin = $org;
            $info->domains = array_unique($info->domains);
            $info->org = (empty($info->org)) ? join(", ", $info->domains) : $info->org;

            $cache[$remote_ip] = $info;
            return $info;
        }

        $info->org = trim($info->org);
    }

    $cache[$remote_ip] = $info;
    return $info;
}





$db = DB::connect("127.0.0.1", 'php', 'localhost', 'arp_assess');

/**
 * Example parsing function to handle a line of input
 *
 * @param string $line The input line from the pipe
 */
function parse_line($line, array &$hosts, callable $domain_fn, callable $host_fn, callable $edge_fn) {
    $parts = explode(" ", $line);

    if (count($parts) < 8 || !str_contains($parts[4], "query[")) {
        return;
    }

    $host = $parts[5];
    $domain = get_domain($host);
    $src = $parts[5];
    if (!isset($hosts[$domain])) {
        $who = find_whois($domain);
        $ip = gethostbyname($host);
        $parts = explode(".", $domain);
        $txt = get_txt_records($domain);
        $full_txt = join(", ", $txt);
        $has_google = false;
        $has_spf = false;
        if (str_contains($full_txt, "google-site-verification")) {
            $has_google = true;
        }
        if (str_contains($full_txt, "v=spf1")) {
            $has_spf = true;
        }

        $domain_fn(NULL, $parts[0], $parts[1], $who->created, $who->expires, $who->registrar, $has_spf, $has_google);
        $hosts[$domain] = true;
    }

}



// Path to the named pipe
$pipePath = '/var/log/dnsmasq.log'; // Replace with your named pipe path

// Ensure the pipe exists and is a named pipe
if (!file_exists($pipePath)) {
    die("Error: The specified path is not a valid named pipe.\n");
}

// Open the named pipe for reading
$pipe = fopen($pipePath, 'r');
if (!$pipe) {
    die("Error: Unable to open named pipe.\n");
}

echo "Listening for input on the named pipe: $pipePath\n";

try {
    // Read the pipe line by line
    while (!feof($pipe)) {
        $line = fgets($pipe); // Read a single line
        if ($line !== false) {
            // Pass the line to the parsing function
            parse_line(trim($line));
        }
    }
} finally {
    // Close the pipe when done
    fclose($pipe);
    echo "Closed the named pipe.\n";
}
