<?php

use ThreadFin\DB\DB;

require "threadfin/core.php";
require "threadfin/db.php";
require "threadfin/http.php";

use \ThreadFin\Core\MaybeStr as MaybeStr;
use \ThreadFin\Core\MaybeO as MaybeO;
use \ThreadFin\Core\Maybe as Maybe;

use const ThreadFin\DB\DB_DUPLICATE_IGNORE;
use const ThreadFin\DB\DB_DUPLICATE_UPDATE;

use function \ThreadFin\Util\panic_if as panic_if;
use function \ThreadFin\Util\not as not;
use function \ThreadFin\Core\partial_right as partial_right;
use function ThreadFin\HTTP\cache_http;
use function ThreadFin\HTTP\http2;
use function \ThreadFin\Util\icontains as icontains;

const BIT_HOSTING = 1;
const BIT_FIRE_TRACK = 2;
const BIT_FIRE_BLOCK = 3;
const BIT_ABUSE_IP = 4;
const BIT_MISP = 5;
const BIT_ALIEN = 6;
const BIT_PHISH = 7;
const BIT_TOPMIL = 8;
const BIT_TOP10MIL = 9;
const BIT_SPF = 10;
const BIT_DKIM = 11;
const BIT_GOOGLE = 12;
const BIT_CLOUDFLARE = 13;
const BIT_WHITELIST = 14;

const VAL_HOSTING = 1 << BIT_HOSTING;
const VAL_FIRE_TRACK = 1 << BIT_FIRE_TRACK;
const VAL_FIRE_BLOCK = 1 << BIT_FIRE_BLOCK;
const VAL_ABUSE_IP = 1 << BIT_ABUSE_IP;
const VAL_MISP = 1 << BIT_MISP;
const VAL_ALIEN = 1 << BIT_ALIEN;
const VAL_PHISH = 1 << BIT_PHISH;
const VAL_TOPMIL = 1 << BIT_TOPMIL;
const VAL_TOP10MIL = 1 << BIT_TOP10MIL;
const VAL_SPF = 1 << BIT_SPF;
const VAL_DKIM = 1 << BIT_DKIM;
const VAL_GOOGLE = 1 << BIT_GOOGLE;
const VAL_CLOUDFLARE = 1 << BIT_CLOUDFLARE;
const VAL_WHITELIST = 1 << BIT_WHITELIST;


class local {
    public function __construct(
        public int $id,
        public string $hostname,
        public string $ip,
        public string $ether,
        public string $ether_type,
    ) {}

    public function __toString() : string {
        return "LocalNode[{$this->id}] {$this->hostname}({$this->ip}):{$this->ether} ({$this->ether_type})";
    }
};

class domain {
    public function __construct(
        public int $id,
        public string $domain,
        public DateTime $created,
        public DateTime $expires,
        public string $registrar,
        public float $score,
        public int $flags,
    ) {}

    public function __toString() : string {
        return "Domain[{$this->id}] {$this->domain}({$this->created->format('Y-m-d')}) {$this->score} ({$this->flags})";
    }
};


class edge {
    public function __construct(
        public int $local_id,
        public int $remote_id,
        public int $dst_port,
        public string $histogram,
        public DateTime $first,
        public DateTime $last,
    ) {}

    public function __toString() : string {
        return "Edge[{$this->local_id}:{$this->remote_id}:{$this->dst_port}] {$this->histogram}";
    }
};

function get_ethernet(string $ipAddress): ?string {
    // Execute the 'arp' command
    $output = shell_exec("ip neigh show $ipAddress 2>/dev/null");

    echo "GET IP ETHER $ipAddress = " . $output . "\n";

    // Check if output contains a valid MAC address
    if (preg_match('/(?:[0-9a-f]{2}:){5}[0-9a-f]{2}/i', $output, $matches)) {
        return $matches[0]; // Return the MAC address
    }

    return null; // MAC address not found
}


// load file into a map
function file_keys(string $filename) : array {
    echo "loading file: [$filename]\n";
    $result = [];
    $x = fopen($filename, "r");
    while ($line = fgets($x)) {
        $result[$line] = 1;
    }
    return $result;
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
        $info->created = date_to_sql_date($matches[1]);
    }
    // expired date
    if (preg_match("/expir[^:]*:\s*(.*)/i", $x(), $matches)) {
        $info->expires = date_to_sql_date($matches[1]);
    }
    // updated date
    if (preg_match("/update[^:]*:\s*(.*)/i", $x(), $matches)) {
        $info->updated = date_to_sql_date($matches[1]);
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

/**
 * convert any date format to a mysql date format, or the empty string
 */
function date_to_sql_date(string $input_date) : string {
    if (strlen($input_date) > 4) {
        $tmp_date = strtotime($input_date);
        if ($tmp_date > 1) {
            return date('Y-m-d', $tmp_date);
        }
        return '';
    }
}

/**
 * return true if domain is in malware list, will reload the malware/phish.txt list every 30 minutes
 */
function is_phish(string $domain) : bool {
    static $list = NULL; 
    static $age = -1; 
    if ($list == NULL or $age < time() - 3600) {
        $list = file_keys("malware/phish.txt");
        $age = time();
        gc_collect_cycles();
    }
    return isset($list[$domain]);
}

/**
 * return true if domain is in whitelist, will reload the malware/whitelist.txt list every 3 days
 */
function is_whitelist(string $domain) : bool {
    static $list = NULL; 
    static $age = -1; 
    if ($list == NULL or $age < time() - (86400*3)) {
        $list = file_keys("malware/whitelist.txt");
        $age = time();
        gc_collect_cycles();
    }
    return isset($list[$domain]);
}


/**
 * return true if domain is in malware list, will reload the malware/phish.txt list every 30 minutes
 */
function is_abuseip(string $ip) : bool {
    static $list = NULL; 
    static $age = -1; 
    // reload the abuse ip data every hour
    if ($list == NULL or $age < time() - (3600)) {
        $list = file_keys("malware/abuseip.txt");
        $age = time();
        gc_collect_cycles();
    }
    return isset($list[$ip]);
}

/**
 * return true if domain is in majestic million list, will reload the malware/majestic_domain.txt list every 30 minutes
 */
function is_majestic(string $domain) : bool {
    static $list = NULL; 
    static $age = -1; 
    // reload the majestic million data every hour
    if ($list == NULL or $age < time() - (3600)) {
        $list = file_keys("malware/majestic_domain.txt");
        $age = time();
        gc_collect_cycles();
    }
    return isset($list[$domain]);
}

/**
 * return true if domain is a public hosting domain, will reload the malware/hosting_domains.txt list every 96 hours
 */
function is_hosting(string $domain) : bool {
    static $list = NULL; 
    static $age = -1; 
    // reload the majestic million data every hour
    if ($list == NULL or $age < time() - (3600*96)) {
        $list = file_keys("malware/hosting_domains.txt");
        $age = time();
        gc_collect_cycles();
    }
    return isset($list[$domain]);
}



/**
 * map an alient vault ioc count number to an arp_asses score
 */
function map_weighted_value($input) {
    // Ensure input is within the valid range
    if ($input < 0 || $input > 30000) {
        throw new InvalidArgumentException("Input must be between 0 and 30000.");
    }

    $input = max($input, 30);

    // Parameters for the scaling
    $max_input = 30;  // Maximum input value
    $max_output = 14; // Maximum output value
    $scale_factor = 0.5; // Factor < 1 gives more weight to lower numbers

    // Apply complementary power scaling for the weighted mapping
    $normalized_input = $input / $max_input; // Normalize to a range of 0 to 1
    $weighted_value = pow($normalized_input, $scale_factor); // Apply inverted weighting
    $output = $weighted_value * $max_output; // Scale to the output range

    // Round to the nearest integer for discrete output
    return round($output);
}



/**
 * @param callable $domain_fn function to write domain to database
 */
function dump_to_db(callable $domain_fn, callable $registrar_fn, array $config, string $domain) : domain {
    $ip       = gethostbyname($domain);
    $who      = find_whois($domain);
    $parts    = explode(".", $domain);
    $len      = count($parts);
    $txt      = get_txt_records($domain);
    $dkim     = get_txt_records("_dkim.$domain");
    $flags    = 0;


    $has_google = (str_contains(join(", ", $txt), "google-site-verification")) ? true : false;
    $has_spf    = (str_contains(join(", ", $txt), "v=spf1")) ? true : false;
    $has_dkim   = (str_contains(join(", ", $dkim), "DMARC")) ? true : false;

    $score  = 0.0;
    if ($has_spf) {
        $score += 1.4;
        $flags += VAL_SPF;
    }
    if ($has_google) {
        $score += 1.2;
        $flags += VAL_GOOGLE;
    }
    if ($has_dkim) {
        $score += 1.1;
        $flags += VAL_DKIM;
    }
    $score += domain_age_to_score(time() - strtotime($who->created));
    if (is_abuseip($ip)) {
        $score += 10.0;
        $flags += VAL_ABUSE_IP;
    }
    if (is_majestic($ip)) {
        $score -= 1.5;
        $flags += VAL_TOPMIL;
    }
    if (is_phish($domain)) {
        $score += 12.0;
        $flags += VAL_PHISH;
    }
    if ($who->cloudflare) {
        $flags += VAL_CLOUDFLARE;
    }

    if (is_whitelist($domain)) {
        $score = 1.0;
        $flags += VAL_WHITELIST;
    } else if (strlen($config['alien_api']) > 20) {
        // get malware details from alienware
        echo "alient vault search $domain\n";
        $headers = ["X-OTX-API-KEY" => $config['alien_api'], 'user-agent' => "Mozilla/5.0 (PHP; Linux; ARM64) arp_assess/0.2 https://github.com/bitslip6/arp_assess"];
        $url = "https://otx.alienvault.com/api/v1/indicators/domain/$domain/general";
        $content = cache_http("cache", (3600*2), "GET", $url, [], $headers);
        $alien = json_decode($content, true);
        if ($alien == false) {
            print_r($content);
            die("ERROR DECODING ALIEN VAULT DATA!\n");
        }
        if (isset($alien['pulse_info']) && $alien['pulse_info']['count'] > 0) {
            $count = intval($alien['pulse_info']['count']);
            echo "alien pulse count: $domain ($count)\n";
            if ($count > 0) {
                $score += map_weighted_value($count);
                $flags += VAL_ALIEN;
            }
        }
    }

    $reg_id = $registrar_fn([NULL, $who->registrar]);
    $domain_id = $domain_fn([NULL, $domain, $parts[$len-1], $who->created, $who->expires, $reg_id, $score, $flags]);
    echo " - ID: $domain_id - insert domain ($reg_id) : {$domain} {$parts[$len-1]}, {$who->created}, {$who->expires}, {$who->registrar}, $score, {$flags} \n";
    $domain = new domain($domain_id, $domain, new DateTime($who->created), new DateTime($who->expires), $who->registrar, $score, $flags);
    return $domain;
}


gc_enable();
$t = file_get_contents("config.json");
$config = json_decode($t, true);
$a = is_array($config);
$n = not($a);
panic_if($n, "Unable to parse config.json, copy config.sample to config.json and configure settings.");

$top_domains   = file_keys("malware/top.txt");


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

$domain_fn = $db->upsert_fn("domain");
$registrar_fn = $db->upsert_fn("registrar");

echo "Loading OUI Data\n";
//$oui = file('oui.csv');
$o = fopen("oui.csv", "r");
$ether_map = [];
while($l = fgets($o)) {
    $p = explode(",", $l);
    $ether_map[trim($p[0])] = trim($p[1]);
}
$sz = count($ether_map);

echo "Db connected, Insert FN created\n";
// echo "domain fn [$domain_fn]\n";

$cache_dst = [];
$cache_host = [];
$cache_src = [];
$cache_edge = [];

$local_fn = $db->upsert_fn("locals");
$host_fn = $db->upsert_fn("host");
while (true) {
    $message     = $queue->convert($recv_fn);
    $host_name   = $message['dst'];
	if (str_ends_with($host_name, "in-addr.arpa")) {
        echo "Reverse ADDR lookup skip\n";
		continue;
    }
    $domain_name = get_domain($host_name);
    $host_ip     = $message['src'];

    // the local node
    if (!isset($cache_src[$host_ip])) {
        $ethernet = get_ethernet($host_ip);
        $prefix   = substr($ethernet, 0, 8);
        $host     = gethostbyaddr($host_ip);
        $oui_name = $ether_map[$prefix]??'unknown';
        $data = [
            'id' => NULL,
            'hostname' => $host,
            'ether' => $ethernet,
            'ether_type' => $oui_name,
            'iptxt' => $host_ip,
            '!ipbin' => "inet_ATON('$host_ip')"];
        $local_id = $local_fn($data);
        echo " - create local node: $local_id - $host_ip, $ethernet, $oui_name, $host\n";
        $cache_src[$host_ip] = new local($local_id, $host, $host_ip, $ethernet, $oui_name);
    }
    $local_node = $cache_src[$host_ip]??NULL;
    echo " + Load node: $local_node\n";
    ASSERT($local_node instanceOf local, "Internal error: local node not created.");


    // the remote domain
    // TODO: need to pull malware state from dump_to_db
    if (!isset($cache_dst[$domain_name])) {
        $cache_dst[$domain_name] = dump_to_db($domain_fn, $registrar_fn, $config, $domain_name);
    }
    $domain = $cache_dst[$domain_name];
    echo " + Load domain: $domain\n";
    ASSERT($domain instanceOf domain, "Internal error: domain node not created.");


    // the remote host
    if (!isset($cache_dst[$host_name])) {
        $who = find_whois($host_ip);
        $reverse_name = gethostbyaddr($host_ip);
        $data = [
            'id' => NULL,
            'hostname' => $host_name,
            '!ip4' => "INET_ATON('$host_ip')",
            'hosting' => $who->org,
            'reverse' => $reverse_name,
            'malware' => $domain->flags];
        $host_id = $host_fn($data);
        echo " - create remote host: $host_id - $host_ip, $host_name, {$who->org}\n";
        $cache_dst[$host_name] = $host_id;
    }
    $remote_node = $cache_dst[$host_name]??NULL;
    echo " + Load node: $local_node\n";
    ASSERT($remote_node instanceOf domain, "Internal error: remote node not created.");



    // the edge
    $edge_key = "$host:$domain:443";
    if (!isset($cache_edge[$edge_key]) || $cache_edge[$edge_key]->last + 300 < time()) {

        $now = new DateTime('now');
        $domain_sql = $db->fetch("SELECT histogram, first, last FROM remote_edge WHERE local_id = {local_id} AND remote_id = {remote_id} AND dst_port = 443", ['local_id' => $local_id, 'remote_id' => $domain_id]);
        $curr_bucket = get_bucket_index($now);
        echo " - load edge [$curr_bucket]\n";
        print_r($domain_sql);
        if ($domain_sql->count() <= 0) {
            $histogram = str_pad("\0", 254, "\0");
            $histogram = setBit($histogram, $curr_bucket);
            $edge_id = $db->insert('remote_edge', ['local_id' => $local_id, 'host_id' => $domain_id, 'dst_port' => 443, 'histogram' => $histogram]);
            echo " - create insert edge: $edge_id ($histogram)\n";
	        print_r($db);
        } else {
            $last_bucket = get_bucket_index(new DateTime($domain_sql->col('last')()));
            $bits = $domain_sql->col('histogram')();
            $bits = clearRange($bits, $last_bucket + 1, $curr_bucket - 1);
            $bits = setBit($bits, $curr_bucket);
            $edge_id = $db->update("remote_edge", ['histogram' => $bits], ['local_id' => $local_id, 'host_id' => $domain_id, 'dst_port', 443]);
            echo " -# update edge $edge_id ($bits)\n";
        }
        $cache_edge[$edge_key] = time();
    }
    
}



