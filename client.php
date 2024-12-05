<?php

use ThreadFin\DB\DB;

require "threadfin/core.php";
require "threadfin/db.php";

use \ThreadFin\Core\MaybeStr as MaybeStr;
use \ThreadFin\Core\MaybeO as MaybeO;
use \ThreadFin\Core\Maybe as Maybe;
use function \ThreadFin\Util\panic_if as panic_if;
use function \ThreadFin\Util\not as not;
use function \ThreadFin\Core\partial_right as partial_right;
use function \ThreadFin\Util\icontains as icontains;


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
    public string $updated = "";
    public string $registrar = "";
    public bool $cloudflare = false;
    public array $domains = [];

    public function __toString()
    {
        return (!empty($this->raw)) 
            ? $this->raw
            : "Whois_Info: $this->as $this->org $this->country $this->cidr $this->net"; 
    }
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
    $sanitized = escapeshellarg($remote_ip);
    /*
    $read_fn = function($x) { return fread($x, 8192); };


    foreach ($whois_servers as $server => $org) {
        $write_ip_fn = partial_right('fputs', "$remote_ip\r\n");
        $x = MaybeStr::of(fsockopen($server, 43, $no, $str, 1))
            ->effect($write_ip_fn)
            ->map($read_fn);
        $info->raw = ($return_raw) ? "" : $x();
        */
    $cmd = "whois $sanitized";
    echo "[$cmd]\n";
    $z = `whois $sanitized`;
    echo "[$z]\n";
    $x = MaybeStr::of($z);


        //  pull the as number from anywhere
        if (preg_match("/AS([0-9]+)/", $x(), $matches)) {
            $info->as = $matches[1];
        }
        // city is common
        if (preg_match("/city[^:]*:\s*(.*)/i", $x(), $matches)) {
            $info->city = $matches[1];
        }
        // created date
        if (preg_match("/creat[^:]*:\s*(.*)/i", $x(), $matches)) {
            $info->created = $matches[1];
        }
        // expired date
        if (preg_match("/expir[^:]*:\s*(.*)/i", $x(), $matches)) {
            $info->expires = $matches[1];
        }
        // updated date
        if (preg_match("/update[^:]*:\s*(.*)/i", $x(), $matches)) {
            $info->updated = $matches[1];
        }
        // registrar date
        if (preg_match("/registrar:\s*(.*)/i", $x(), $matches)) {
            $info->registrar = $matches[1];
        }
        // so is country
        if (preg_match("/country[^:]*:\s*(.*)/i", $x(), $matches)) {
            $info->country = icontains($matches[1], ["world"])  ? "global" : $matches[1];
        }
        // postal is sometimes in an address field
        if (preg_match("/postal\s?code[^:]*:\s*(.*)/i", $x(), $matches)) {
            $info->zip = $matches[1];
        }
        // cloudflare
        if (preg_match("/cloudflare/i", $x(), $matches)) {
            $info->cloudflare = true;
        }
        if (empty($info->zip) && preg_match("/address:[^:]*:.*?(\d{5})/i", $x(), $matches)) {
            $info->zip = $matches[1];
        }
        // pull cidr from anywhere
        if (empty($info->cidr) && preg_match("/([0-9.:]+\/\d+)/i", $x(), $matches)) {
            $info->cidr = $matches[1];
        }

        // pull the net range
        if (preg_match("/([\d.:]+\s+-\s+[\d.:]+)/i", $x(), $matches)) {
            $info->net = $matches[1];
        }

        // pull the org name from likely places
        if (preg_match("/(org|descr|owner|netname)[^:]*:+\s*(.*)/i", $x(), $matches)) {
            $info->org .= $matches[1] . "\n";
        }
        // pull all email addresses
        if (preg_match("/[\w_\.-]+\@(\w+\.\w+)/i", $x(), $matches)) {
            $info->domains[] = $matches[1];
        }

        if (!empty($info->as) || !empty($info->org) || !empty($info->country)) {
            $info->arin = $info->org;
            $info->domains = array_unique($info->domains);
            $info->org = (empty($info->org)) ? join(", ", $info->domains) : $info->org;

            $cache[$remote_ip] = $info;
            return $info;
        }

        $info->org = trim($info->org);
    print_r($info);
	die("chains\n");

    $cache[$remote_ip] = $info;
    return $info;
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



// convert a domain created age in seconds to a malware score
function domain_age_to_score(int $seconds) : float {

    // Define the minimum and maximum seconds (1 day to 1 year)
    $minSeconds = 86400;           // 1 day in seconds
    $maxSeconds = 86400 * 365 * 1; // 1 year in seconds

    // Define the minimum and maximum output values
    $minOutput = 0.0;
    $maxOutput = 5.0;

    // Validate the input
    if (!is_numeric($seconds)) {
        trigger_error("Input must be a numeric value representing seconds.", E_USER_WARNING);
        return 0.0;
    }

    if ($seconds < $minSeconds || $seconds > $maxSeconds) {
        return 0.0;
    }

    // Calculate the proportion of the input within the range
    $proportion = ($seconds - $minSeconds) / ($maxSeconds - $minSeconds);

    // Map the proportion to the output range (5 to 0)
    $output = $maxOutput - ($proportion * ($maxOutput - $minOutput));

    return $output;
}


function dump_to_db($domain_fn, $registrar_fn, $msg) : ?string {
    //$src_host       = gethostbyaddr($msg['src']);
    $ip       = gethostbyname($msg['dst']);
    $domain   = get_domain($msg['dst']);
    $who      = find_whois($domain);
    $parts    = explode(".", $msg['dst']);
    $len      = count($parts);
    $txt      = get_txt_records($domain);
    $dkim     = get_txt_records("_dkim.$domain");

    if (strlen($who->created) > 4) {
        $tmp_date = strtotime($who->created);
        if ($tmp_date > 1) { $who->created = date('Y-m-d', $tmp_date); }
    }
    if (strlen($who->expires) > 4) {
        $tmp_date = strtotime($who->expires);
        if ($tmp_date > 1) { $who->expires = date('Y-m-d', $tmp_date); }
    }


    $has_google = false;
    $has_spf    = false;
    $has_dkim   = false;
    if (str_contains(join(", ", $txt), "google-site-verification")) {
        $has_google = true;
    }
    if (str_contains(join(", ", $txt), "v=spf1")) {
        $has_spf = true;
    }
    if (str_contains(join(", ", $dkim), "DMARC")) {
        $has_dkim = true;
    }

    print_r($who);

    $score  = 0.0;
    $score += ((!$has_spf) ? 1 : 0) * 1.4;
    $score += ((!$has_google) ? 1 : 0) * 1.2;
    $score += ((!$has_dkim) ? 1 : 0) * 1.2;
    $score += domain_age_to_score(time() - strtotime($who->created));
    // add score if the domain is modified in the last 60 days
    $score += domain_age_to_score((300 * 86400) + (time() - strtotime($who->updated)));

    $reg_id = $registrar_fn([NULL, $who->registrar]);
    echo " - insert domain ($reg_id) : {$parts[$len-2]} {$parts[$len-1]}, {$who->created}, {$who->expires}, {$who->registrar}, $has_spf, $has_dkim, $has_google, $score, {$who->cloudflare} \n";
    $result = $domain_fn([NULL, $parts[$len-2], $parts[$len-1], $who->created, $who->expires, $reg_id, $has_spf & $has_dkim, $has_google, $score, $who->cloudflare]);
    echo "result: [$result]\n";
    return $domain;
}


$t = file_get_contents("config.json");
$config = json_decode($t, true);
$a = is_array($config);
$n = not($a);
panic_if($n, "Unable to parse config.json, copy config.sample to config.json and configure settings.");

// Open the named pipe for reading
//$pipe = fopen($config['dnsmasq_log'], 'r');
//panic_if(not(is_resource($pipe)), "Error: Unable to open named pipe {$config['dnsmasq_log']}.\n");
//echo "Listening for input on the named pipe: {$config['dnsmasq_log']}\n";
//die();

$queue_id = ftok('config.json', 'R');
$queue = MaybeO::of(msg_get_queue($queue_id, 0666));

$recv_fn = function($queue) {
    msg_receive($queue, 1, $type, 1024*32, $message, false, 0, $error);
    if (empty($message)) {
        echo "message queue recieve failed\n";
        return;
    }
    $msg = json_decode($message, true);
    if (empty($msg)) {
        echo "message decode failed\n";
        return;
    }

    echo "recieved message: [$message]\n";

    return $msg;
};


$db = DB::connect($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
$db->enable_log(true);

//public function bulk_fn(string $table, array $columns, bool $ignore_duplicate = true) : callable { 
$domain_fn = $db->insert_fn("domain", ['id', 'domain', 'tld', 'created', 'expires', 'registrar', 'email', 'google_verify', 'score', 'cloudflare'], false);
$registrar_fn = $db->insert_fn("registrar", ['id', 'registrat'], false);
print_r($domain_fn);
print_r($registrar_fn);

echo "Db connected, Insert FN created\n";
// echo "domain fn [$domain_fn]\n";

while (true) {
    $message = $queue->convert($recv_fn);
    //print_r($message);
    //continue;
    $domain = dump_to_db($domain_fn, $registrar_fn, $message);
    echo "ERR: ($domain)\n";
    sleep(1);
    print_r($db);
}



/*
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
    */

