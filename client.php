<?php

use ThreadFin\DB\DB;

require "threadfin/core.php";
require "threadfin/db.php";

use \ThreadFin\Core\MaybeStr as MaybeStr;
use \ThreadFin\Core\MaybeO as MaybeO;
use \ThreadFin\Core\Maybe as Maybe;

use const ThreadFin\DB\DB_DUPLICATE_IGNORE;
use const ThreadFin\DB\DB_DUPLICATE_UPDATE;

use function \ThreadFin\Util\panic_if as panic_if;
use function \ThreadFin\Util\not as not;
use function \ThreadFin\Core\partial_right as partial_right;
use function \ThreadFin\Util\icontains as icontains;

function get_ethernet(string $ipAddress): ?string {
    // Execute the 'arp' command
    $output = shell_exec("arp -n $ipAddress 2>/dev/null");

    // Check if output contains a valid MAC address
    if (preg_match('/(?:[0-9a-f]{2}:){5}[0-9a-f]{2}/i', $output, $matches)) {
        return $matches[0]; // Return the MAC address
    }

    return null; // MAC address not found
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
 * Get the bucket index (0-287) corresponding to a given DateTime.
 *
 * @param DateTime $dt The date-time object.
 * @return int Bucket index (0 to 287).
 */
function get_bucket_index(DateTime $dt): int {
    $secondsSinceMidnight = ($dt->format('H') * 3600) + ($dt->format('i') * 60) + $dt->format('s');
    return intdiv($secondsSinceMidnight, 300); // 300s = 5min
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
    $z = `whois $sanitized`;
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
        $info->zip = intval($matches[1]);
    }
    // cloudflare
    if (preg_match("/cloudflare/i", $x(), $matches)) {
        $info->cloudflare = true;
    }
    if (empty($info->zip) && preg_match("/address:[^:]*:.*?(\d{5})/i", $x(), $matches)) {
        $info->zip = intval($matches[1]);
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

    //print_r($who);

    $score  = 0.0;
    $score += ((!$has_spf) ? 1 : 0) * 1.4;
    $score += ((!$has_google) ? 1 : 0) * 1.2;
    $score += ((!$has_dkim) ? 1 : 0) * 1.2;
    $score += domain_age_to_score(time() - strtotime($who->created));
    // add score if the domain is modified in the last 60 days
    $score += domain_age_to_score((300 * 86400) + (time() - strtotime($who->updated)));

    $reg_id = $registrar_fn([NULL, $who->registrar]);
    $result = $domain_fn([NULL, $parts[$len-2], $parts[$len-1], $who->created, $who->expires, $reg_id, $has_spf & $has_dkim, $has_google, $score, $who->cloudflare]);
    echo " - ID: $result - insert domain ($reg_id) : {$parts[$len-2]} {$parts[$len-1]}, {$who->created}, {$who->expires}, {$who->registrar}, $has_spf, $has_dkim, $has_google, $score, {$who->cloudflare} \n";
    return $result;
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
echo "Config Loaded\n";

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
echo "DB Connected\n";

//public function bulk_fn(string $table, array $columns, bool $ignore_duplicate = true) : callable { 

$domain_fn = function(array $data) use ($db) {
	/*
    $sql = $db->fetch("SELECT id FROM registrar WHERE registrar = {registrar}", $data);
    if ($sql->count() < 1) {
        $reg_id = $db->insert('registrar', ['id' => NULL, 'registrar' => $data['registrar']], DB_DUPLICATE_IGNORE);
    } else {
        $reg_id = $sql->col('id')();
    }

    $data['registrar'] = $reg_id;
	 */
	print_r($data);
    $domain_id = $db->insert("domain", $data);//, DB_DUPLICATE_UPDATE);
};

$registrar_fn = $db->insert_fn("registrar", ['id', 'registrar'], false);
//$local_fn = $db->insert_fn("host", ['id', 'hostname', 'ip4'

echo "Loading OUI Data\n";
//$oui = file('oui.csv');
echo "open\n";
$o = fopen("oui.csv", "r");
$ether_map = [];
while($l = fgets($o)) {
    $p = explode(",", $l);
    $ether_map[trim($p[0])] = trim($p[1]);
}
$sz = count($ether_map);
echo "mapped! [$sz]\n";
/*
$ether_map = array_reduce($oui, function ($carry, $line) {
    $p = explode(",", $line);
    $carry[trim($p[0])] = trim($p[1]);
    return $carry;
}, []);
 */

echo "Db connected, Insert FN created\n";
// echo "domain fn [$domain_fn]\n";

$cache_dst = [];
$cache_src = [];
$cache_edge = [];
while (true) {
    $message = $queue->convert($recv_fn);
    $domain = get_domain($message['dst']);
    $host = $message['src'];
    // the local node
    if (!isset($cache_src[$host])) {
        $ethernet = get_ethernet($host);
        $hostname = gethostbyaddr($host);
        $local_sql = $db->fetch("SELECT id FROM locals WHERE ether = {ethernet}", ['ethernet' => $ethernet]);
        echo " - load local\n";
        if ($local_sql->count() <= 0) {
            $ether_prefix = substr($ethernet, 0, 8);
            $local_id = $db->insert('locals', ['id' => NULL, 'hostname' => $hostname, 'ether' => $ethernet, 'ether_type' => $ether_map[$ether_prefix]??'unknown']);
            echo " - insert local\n";
        } else {
            $local_id = $local_sql->col('id')();
        }
        $cache_src[$host] = [$ethernet, gethostbyaddr($host), $local_id];
    }

    // the remote node
    if (!isset($cache_dst[$domain])) {
        $domain_sql = $db->fetch("SELECT id FROM domain WHERE domain = {domain}", ['domain' => $domain]);
        echo " - load remote\n";
        if ($domain_sql->count() <= 0) {
            $domain_id = dump_to_db($domain_fn, $registrar_fn, $message);
            echo " - insert remote\n";
        } else {
            $domain_id = $domain_sql->col('id')();
        }
        $cache_dst[$domain] = [$ethernet, gethostbyaddr($host), $local_id];
    }


    // the edge
    $edge_key = "$host:$domain:443";
    if (!isset($cache_edge[$edge_key]) || $cache_edge[$edge_key] + 300 < time()) {

        $domain_sql = $db->fetch("SELECT histogram, first, last FROM remote_edge WHERE local_id = {local_id} AND remote_id = {remote_id} AND dst_port = 443", ['domain' => $domain]);
        echo " - load edge\n";
	print_r($domain_sql);
        if ($domain_sql->count() <= 0) {
            $edge_id = $db->insert('remote_edge', ['local_id' => $local_id, 'host_id' => $domain_id, 'dst_port' => 443, 'histogram' => str_pad("\0", 254, "\0"), 'first' => NULL, 'last' => NULL]);
            echo " - insert edge: $edge_id\n";
	    print_r($db);
        } else {
            $now = new DateTime('now');
            $curr_bucket = get_bucket_index($now);
            $last_bucket = get_bucket_index(new DateTime($domain_sql->col('last')()));
            $bits = $domain_sql->col('histogram')();
            $bits = clearRange($bits, $last_bucket + 1, $curr_bucket - 1);
            $bits = setBit($bits, $curr_bucket);
            $db->update("remote_edge", ['histogram' => $bits], ['local_id' => $local_id, 'host_id' => $domain_id, 'dst_port', 443]);
            echo " - update edge\n";
        }
        $cache_edge[$edge_key] = time();
    }
    
}



