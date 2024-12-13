<?php

/**
 * NOTES: need to update phishing from hosting domains and link shortener domains, etc
 * 
 * select h.hostname, inet_ntoa(h.ip4), h.malware, l.iptxt, l.hostname, l.ether_type, e.first, e.last, d.score, d.note, r.registrar from host as h join remote_edge as e on e.host_id = h.id join locals as l on e.local_id = l.id join domain as d on h.domain_id = d.id join registrar as r on d.registrar = r.id where (h.malware & 1<<6) > 0 or (d.malware & 1<<6) > 0;
 * 
 * todo: web interface, FFT beaconing detection, dns twist detection,
 * detect beaconing to multiple domains with the same registrar
 * detect beaconing to multiple domains registered in the last year
 * block NULL dns requests
 * check TXT dns requests
 * check SVR dns requests
 * block DNS to the internet except from authorized hosts
 * 
 * 
 */

use ThreadFin\DB\DB;

// ini_set('zend.assertions', '1');
ini_set('assert.active', '1');
ini_set('assert.warning', '1');
ini_set('assert.exception', '1');

require "threadfin/core.php";
require "threadfin/db.php";
require "threadfin/http.php";
require "common.php";

const DISABLED_MITRE = [
'T1012',
'T1018',
'T1053',
'T1593',
'T1596',
'T1594',
'T1518',
'T1106',
'T1071'
];

const ALIEN_MAX_DAYS = 90;

use \ThreadFin\Core\MaybeStr as MaybeStr;
use \ThreadFin\Core\MaybeO as MaybeO;
use \ThreadFin\Core\Maybe as Maybe;

use const ThreadFin\DB\DB_DUPLICATE_IGNORE;
use const ThreadFin\DB\DB_DUPLICATE_UPDATE;
use const ThreadFin\DB\DB_FETCH_INSERT_ID;
use const ThreadFin\DB\DB_FETCH_NUM_ROWS;
use const ThreadFin\DB\DB_FETCH_SUCCESS;
use ThreadFin\DB\SQL as SQL;

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
const BIT_WARNING = 8;
const BIT_TOPMIL = 9;
const BIT_TOP10MIL = 10;
const BIT_SPF = 11;
const BIT_DKIM = 12;
const BIT_GOOGLE = 13;
const BIT_CLOUDFLARE = 14;
const BIT_WHITELIST = 15;
const BIT_TRACKING = 16;

const VAL_HOSTING = 1 << BIT_HOSTING;
const VAL_FIRE_TRACK = 1 << BIT_FIRE_TRACK;
const VAL_FIRE_BLOCK = 1 << BIT_FIRE_BLOCK;
const VAL_ABUSE_IP = 1 << BIT_ABUSE_IP;
const VAL_MISP = 1 << BIT_MISP;
const VAL_ALIEN = 1 << BIT_ALIEN;
const VAL_PHISH = 1 << BIT_PHISH;
const VAL_WARNING = 1 << BIT_WARNING;
const VAL_TOPMIL = 1 << BIT_TOPMIL;
const VAL_TOP10MIL = 1 << BIT_TOP10MIL;
const VAL_SPF = 1 << BIT_SPF;
const VAL_DKIM = 1 << BIT_DKIM;
const VAL_GOOGLE = 1 << BIT_GOOGLE;
const VAL_CLOUDFLARE = 1 << BIT_CLOUDFLARE;
const VAL_WHITELIST = 1 << BIT_WHITELIST;
const VAL_TRACKING = 1 << BIT_TRACKING;


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
        public int $category
    ) {}

    public static function from_sql(SQL $result) : domain {
        $x = $result->as_array();
        $domain = new domain(
            $x['id'],
            $x['domain'],
            new DateTime($x['created']), 
            new DateTime($x['expires']), 
            $x['registrar'],
            $x['score'],
            $x['malware'],
            $x['category_id']);
        return $domain;
    }

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
    public ?string $created = null;
    public ?string $expires = null;
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
 * recieve a message from a message queue, and return array
 */
function recieve_message(?SysvMessageQueue $queue) : ?array {
    msg_receive($queue, 1, $type, 1024*32, $message, false, 0, $error);
    if (empty($message)) {
        echo "ERR: message queue recieve failed\n";
        return null;
    }
    $msg = json_decode($message, true);
    if (empty($msg)) {
        echo "ERR: message decode failed\n";
        return null;
    }

    return $msg;
};



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
    if (preg_match("/creat[^:\]]*:\s*(.*)/i", $x(), $matches)) {
        $info->created = date_to_sql_date($matches[1]);
    }
    // expired date
    if (preg_match("/expir[^:\]]*:\s*(.*)/i", $x(), $matches)) {
        $info->expires = date_to_sql_date($matches[1]);
    }
    // updated date
    if (preg_match("/update[^:\]]*:\s*(.*)/i", $x(), $matches)) {
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
    if (preg_match("/(org|descr|owner|netname|registrant)[^:\]]*:+\s*(.*)/i", $x(), $matches)) {
        $info->org .= $matches[1] . " ";
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
 * TODO: need to move this to host info...
 * TODO: need to add all hosting domains to whitelist
 * TODO: need to handle hosting domains differently...
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
 * return true if host is a tracking host
 */
function is_tracking(string $host, bool $append = false) : bool {
    static $list = NULL; 
    static $age = -1; 
    if ($list == NULL or $age < time() - 86400) {
        $list = file_keys("malware/tracking.txt");
        $age = time();
        gc_collect_cycles();
    }
    if ($append) {
        $list[$host] = count($list) + 1;
        file_put_contents("malware/tracking.txt", join("\n", array_keys($list)), LOCK_EX);
    }
    return isset($list[$host]);
}

/**
 * return true if host is a tracking host
 */
function is_hosting(string $host) : bool {
    static $list = NULL; 
    static $age = -1; 
    if ($list == NULL or $age < time() - 86400*2) {
        $list = file_keys("malware/hosting_domains.txt");
        $age = time();
        gc_collect_cycles();
    }
    return isset($list[$host]);
}


/**
 * TODO: need to move this to host info...
 * TODO: need to add all hosting domains to whitelist
 * TODO: need to handle hosting domains differently...
 * return true if domain is in malware list, will reload the malware/phish.txt list every 30 minutes
 */
function is_warning(string $domain) : bool {
    static $list = NULL; 
    static $age = -1; 
    if ($list == NULL or $age < time() - 86400*7) {
        $list = file_keys("malware/warning_domain.txt");
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
    $w = isset($list[$domain]);
	return $w;
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
function is_majestic(string $domain) : int {
    static $list = NULL; 
    static $age = -1; 
    // reload the majestic million data every hour
    if ($list == NULL or $age < time() - (3600)) {
        $list = file_keys("malware/majestic_domain.txt");
        $age = time();
        gc_collect_cycles();
    }
    return isset($list[$domain]) ? $list[$domain] : 0;
}



/**
 * map an alient vault ioc count number to an arp_asses score
 */
function alien_count_to_score($input) {
    // Ensure input is within the valid range
    if ($input < 0 || $input > 30000) {
        throw new InvalidArgumentException("Input must be between 0 and 30000.");
    }

    $input = max($input, 30);

    // Parameters for the scaling
    $max_input = 20;  // Maximum input value
    $max_output = 5; // Maximum output value
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
function dump_to_db(callable $domain_fn, callable $registrar_fn, array $config, string $host) : domain {
    echo " @@ dump domain: $host\n";
    $domain   = get_domain($host);
    $ip       = gethostbyname($domain);
    $who      = find_whois($domain);
    $parts    = explode(".", $domain);
    $len      = count($parts);
    $txt      = get_txt_records($domain);
    $dkim     = get_txt_records("_dkim.$domain");
    $flags    = 0;
    $rank     = is_majestic($domain);
    echo "    @@ dump domain: $domain, $ip, ($rank)\n";
    $raw_net  = cache_http("net_cache", (86400*30), "GET", "https://informatics.netify.ai/api/v2/lookup/domains/$domain");
    $net_data = json_decode($raw_net, true);
    $cat_id   = get_category_id('netify', $net_data['data']['category']['label'] ?? 254, 0);
    


    $has_google = (str_contains(join(", ", $txt), "google-site-verification")) ? true : false;
    $has_spf    = (str_contains(join(", ", $txt), "v=spf1")) ? true : false;
    $has_dkim   = (str_contains(join(", ", $dkim), "DMARC")) ? true : false;

    $score  = 0.0;
    $note = "";
    if (! $has_spf) {
        $score += 1.4;
        $flags += VAL_SPF;
        $note .= "SPF,";
    }
    if (! $has_google) {
        $score += 1.2;
        $flags += VAL_GOOGLE;
        $note .= "GOG,";
    }
    if (! $has_dkim) {
        $score += 1.1;
        $flags += VAL_DKIM;
        $note .= "DKM,";
    }
    // if we know the domain creation time, and it looks created recently, add to the score
    $time = strtotime($who->created);
    if ($time > time() - (86400*400) && $time < time()) {
        $score += domain_age_to_score(time() - strtotime($who->created));
        $note .= "DOMSC:$score,";
    }
    if ($who->cloudflare) {
        $flags += VAL_CLOUDFLARE;
        $note .= "FLAR,";
    }
    if (is_abuseip($ip)) {
        $score += 10.0;
        $flags += VAL_ABUSE_IP;
        $note .= "ABUSE,";
    }
    if ($rank > 0) {
        $score -= 1.5;
        $flags += VAL_TOPMIL;
        $note .= "MAJ,";
    }
    if (is_whitelist($domain)) {
        $score = 1.0;
        $flags += VAL_WHITELIST;
        $note .= "WHIT,";
    }
    else if (is_tracking($host) || is_tracking($domain)) {
        $score += 1.1;
        $flags += VAL_TRACKING;
        $note .= "TRK,";
    } // spammy domains
    else if (is_warning($domain) || is_warning($host)) {
        $score += 3.3;
        $flags += VAL_WARNING;
        $note .= "WARN,";
    }
    else if (is_hosting($domain)) {
        $score += 2.1;
        $flags += VAL_HOSTING;
        $note .= "CDN,";
    }
    else if (stristr($who->registrar, "markmonitor") === false) {
        // is this unknown domain phishing?
        if (is_phish($host) || is_phish($domain)) {
            $score += 12.0;
            $flags += VAL_PHISH;
            $note .= "PHISH,";
        }
        // unknown ... check alien vault
        else {
            if (strlen($config['alien_api']) > 20) {
                // get malware details from alienware
                // echo "alien vault search $domain\n";
                $headers = ["X-OTX-API-KEY" => $config['alien_api'], 'user-agent' => "Mozilla/5.0 (PHP; Linux; ARM64) arp_assess/0.2 https://github.com/bitslip6/arp_assess"];
                $url = "https://otx.alienvault.com/api/v1/indicators/domain/$domain/general";
                $content = cache_http("cache", (3600*2), "GET", $url, [], $headers);
                if (strlen($content) > 10) {
                    $alien = json_decode($content, true);
                    if ($alien == false) {
                        echo ("\n\nERROR DECODING ALIEN VAULT DATA! ($domain) resp len:" . strlen($content) . "\n");
                    }
                    if (isset($alien['pulse_info']) && $alien['pulse_info']['count'] > 0) {
                        // filter out to just pulses updated in the last 4 months
                        /*
                        $active_pulses = array_filter($alien['pulse_info']['pulses'], function ($x) {
                            $parts = explode(".", $x['modified']);
                            $mod = strtotime($parts[0]);
                            $active = $mod > (time() - (86400 * 120));
                            if ($active) {
                                // active and with attack ids...
                                $attacks = array_filter($x['attack_ids'], 'alien_attack_id_filter');
                                return count($attacks) > 0;
                            }
                            return false;
                        });
                        */
                        $pulse_score = array_reduce($alien['pulse_info']['pulses'], function ($carry, $pulse) {
                            $attacks = array_filter($pulse['attack_ids'], 'alien_attack_id_filter');
                            if (count($attacks) > 0) {
                                $created = DateTime::createFromFormat("Y-m-d\TH:i:s.u", $pulse['created']);
                                if ($created) {
                                    $age = ALIEN_MAX_DAYS - ((time() - $created->getTimestamp()) / 86400);
                                    $age = max($age, 0);
                                    $attack_score = $carry + pow(($age / ALIEN_MAX_DAYS), 0.8) * 3;
                                    echo " **** Attack age: $age - $attack_score\n";
                                    $carry += $attack_score;
                                }
                            }

                            return $carry;

                        }, 0);
                        if (isset($alien['validation']) && count($alien['validation']) > 0) {
                            $flags += VAL_WHITELIST;
                            $note .= "AWHIT,";
                        }
                        else if ($pulse_score > 0) {
                            $score += alien_count_to_score($pulse_score);
                            $note .= "ALIEN,";
                            $flags += VAL_ALIEN;
                        }
                    }
                }
            }
            if (strlen($config['virustotal_api']) > 20) {

                $headers = ["X-OTX-API-KEY" => $config['alien_api'], 'user-agent' => "Mozilla/5.0 (PHP; Linux; ARM64) arp_assess/0.2 https://github.com/bitslip6/arp_assess"];
                $url = "https://www.virustotal.com/api/v3/domains/$domain";
                $content = cache_http("cache", (3600*2), "GET", $url, [], $headers);
                if (strlen($content) > 10) {
                    $vt = json_decode($content, true);
                    if ($vt == false || !isset($vt['data']['attributes'])) {
                        echo "\n\nERROR DECODING VIRUS TOTAL DATA! ($domain) resp len:" . strlen($content) . "\n";
                    }
                    else {
                        echo " ++ add virus total data for [$domain]\n";
                        $attr = $vt['data']['attributes'];

                        // pull category from virus total
                        if (isset($attr['categories'])) {
                            $cat_id = 0;
                            foreach ($attr['categories'] as $source => $value) {
                                $cat_id = get_category_id($source, $value, $cat_id);
                            }
                        }

                        // calculate a domain score based on intelligence feeds
                        if (isset($attr['last_analysis_stats'])) {
                            $score += alien_count_to_score($attr['last_analsis_stats']['malicious']);
                            $score += alien_count_to_score($attr['last_analsis_stats']['suspicious']) / 3;
                            $score -= alien_count_to_score($attr['last_analsis_stats']['harmless']) / 10;
                        }

                        // calculate a domain score based on human votes
                        if (isset($attr['total_votes'])) {
                            $score += alien_count_to_score($attr['total_votes']['malicious']);
                            $score -= alien_count_to_score($attr['total_votes']['harmless']);

                            // note this domain as a tracking domain...
                            if ($attr['total_votes']['harmless'] > 32 && $attr['total_votes']['malicious'] < 2) {
                                is_tracking($domain, true);
                            }
                        }
                    }
                }
            }
        }
    }

    $note     .= $net_data['data']['category']['tag'] ?? 'UNKN';
    $reg_id    = $registrar_fn([NULL, $who->registrar]);
    if (empty($who->created)) { $who->created = NULL; }
    if (empty($who->expires)) { $who->expires = NULL; }
    $domain_id = $domain_fn([NULL, $domain, $parts[$len-1], $who->created, $who->expires, $reg_id, $score, $flags, $note, $rank, $cat_id]);
    echo "    @@ DOMAIN_ID: $domain_id ($domain} {$who->expires} [$note]\n";
    $domain = new domain($domain_id, $domain, new DateTime($who->created), new DateTime($who->expires), $who->registrar, $score, $flags, $cat_id);
    return $domain;
}


gc_enable();
$config = json_decode(file_get_contents("config.json"), true);
$a      = is_array($config);
panic_if(not($a), "Unable to parse config.json, copy config.sample to config.json and configure settings.");
echo "~ Config Loaded\n";

$queue  = MaybeO::of(msg_get_queue(ftok('config.json', 'R'), 0666));
echo "~ Msg Queue Connected\n";

$db = DB::connect($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
$db->enable_log(false);
echo "~ DB Connected\n";


$ether_map  = [];
$cache_dst  = [];
$cache_host = [];
$cache_src  = [];
$cache_edge = [];

$domain_fn    = $db->upsert_fn("domain");
$registrar_fn = $db->upsert_fn("registrar");
$local_fn     = $db->upsert_fn("locals");
$host_fn      = $db->upsert_fn("host");
//$r_edge_fn    = $db->upsert_fn("remote_edge");

echo "~ DB functions created\n";

echo "# Loading OUI Data...\n";
$o = fopen("oui.csv", "r");
while($l = fgets($o)) {
    $p = explode(",", $l);
    $ether_map[trim($p[0])] = trim($p[1]);
}
$sz = count($ether_map);


echo "# Reading Messages...\n";
$empty_bits = '';
for ($i=0; $i<253; $i++) {
    $empty_bits .= chr(0);
}
while (true) {
    $message     = $queue->convert('recieve_message');
    $host_name   = $message['dst'];
    $domain_name = get_domain($host_name);
    $host_ip     = $message['src'];
	if (str_ends_with($host_name, "in-addr.arpa")) {
		continue;
    }

    // the local node
    if (!isset($cache_src[$host_ip])) {
        $ethernet = get_ethernet($host_ip);
        if (empty($ethernet)) {
            continue;
        }
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
        $cache_src[$host_ip] = new local($local_id, $host, $host_ip, $ethernet, $oui_name);
    }
    $local_node = $cache_src[$host_ip]??NULL;
    $local_id = $local_node->id;
    ASSERT($local_node instanceOf local, "ERR: Internal Error: local node not created.");


    // the remote domain
    if (!isset($cache_dst[$domain_name])) {
        $res = $db->fetch("SELECT * FROM domain WHERE domain = {name}", ["name" => $domain_name]);
        if ($res->empty()) {
            $domain = dump_to_db($domain_fn, $registrar_fn, $config, $host_name);
            if ($domain->id < 1) {
                echo "ERR: dumping domain to db: [$host_name]\n";
                print_r($db->errors);
                $db->errors = [];
            }
        } else {
            $domain = domain::from_sql($res);
            echo "Loaded DOMAIN: $domain\n";
        }
        $cache_dst[$domain_name] = $domain;
    }
    $domain = $cache_dst[$domain_name];
    ASSERT($domain instanceOf domain, "ERR: Internal error: domain node not created.");


    // the remote host
    if (!isset($cache_dst["HOST:$host_name"])) {
        $remote_ip = gethostbyname($host_name);
        if (!preg_match("/^\d+\.\d+\.\d+\.\d+$/", $remote_ip)) {
            echo " - NOT IPv4 - $host_name -> $remote_ip\n";
            continue;
        }
        $who = find_whois($remote_ip);
        $reverse_name = gethostbyaddr($remote_ip);
        $data = [
            'id' => NULL,
            'hostname' => $host_name,
            '!ip4' => "INET_ATON('$remote_ip')",
            'hosting' => $who->org,
            'reverse' => $reverse_name,
            'domain_id' => $domain->id,
            'malware' => $domain->flags];
        $host_id = $host_fn($data);
        if ($host_id < 0) {
            echo "ERR: unable to create host\n";
            print_r($data);
            print_r($db->errors);
            $db->errors = [];
        }
        echo " - create remote host: $host_id - $host_ip, $host_name, {$who->org}\n";
        $cache_dst["HOST:$host_name"] = $host_id;
    }
    $remote_node_id = $cache_dst["HOST:$host_name"]??NULL;
    ASSERT($remote_node_id > 0, "ERR: Internal error: remote node not created.");


    // the edge
    $edge_key = "$host_ip:$remote_note_id:443";
    if (!isset($cache_edge[$edge_key]) || ($cache_edge[$edge_key]->last->getTimeStamp() + 300) < time()) {

        $now = new DateTime('now');
        $curr_bucket = get_bucket_index($now);
        echo "EDGE- {$local_node->id}->{$remote_node_id} @$curr_bucket\n";
        $domain_sql = $db->fetch("SELECT histogram, first, last FROM remote_edge WHERE local_id = {local_id} AND host_id = {host_id} AND dst_port = 443", ['local_id' => $local_node->id, 'host_id' => $remote_node_id]);
        echo $db->last_stmt . "\n";

        if ($domain_sql->count() <= 0) {
            $histogram = setBit($empty_bits, $curr_bucket);
            $success = $db->insert("remote_edge", ['histogram' => $histogram, 'local_id' => $local_id, 'host_id' => $remote_node_id, 'dst_port' => 443], DB_FETCH_SUCCESS);
            if (!$success) {
                print_r($db->errors);
                $db->errors = [];
                echo "ERR inserting remote_edge\n";
            }
            $edge = new edge($local_node->id, $remote_node_id, 443, $histogram, $now, $now);
        } else {
            $last_bucket = get_bucket_index(new DateTime($domain_sql->col('last')()));
            $bits = $domain_sql->col('histogram')();
            if (empty($bits)) {
                $bits = $empty_bits;
            }
            echo " =-= {$domain_sql->col('last')()} $last_bucket, $curr_bucket\n";
            $bits = clearRange($bits, $last_bucket + 1, $curr_bucket - 1);
            $histogram = setBit($bits, $curr_bucket);
            $num_rows = $db->update("remote_edge", ['histogram' => $histogram], ['local_id' => $local_id, 'host_id' => $remote_node_id, 'dst_port' => 443], DB_FETCH_NUM_ROWS);
            if ($num_rows < 1) {
                print_r($db->errors);
                $db->errors = [];
            }
            $edge = new edge($local_node->id, $remote_node_id, 443, $histogram, new DateTime($domain_sql->col('last')()), $now);
        }
        $cache_edge[$edge_key] = $edge;
    }
    
}



