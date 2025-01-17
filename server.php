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

class Edge {

    public function __construct(
        public string $src,
        public string $dst,
        public int $timestamp) {
    }

    public function get_5min_bucket() : int {
        // convert to number of seconds in a day
        $time_in_day = $this->timestamp % 86400;
        // get the 5 minute bucket the time stamp is in
        $bucket = floor($time_in_day / 60 / 5);
        return $bucket;
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

function not_azure(?Edge $edge) : bool {
	if (empty($edge) || str_ends_with($edge->dst, "azure.com")) {
		return false;
	}
	return true;
}


/**
 * Example parsing function to handle a line of input
 *
 * @param string $line The input line from the pipe
 */
//function parse_line($line, array &$hosts, callable $domain_fn, callable $host_fn, callable $edge_fn) {
function parse_line($line) : MaybeO {
    $parts = explode(" ", $line);

    if (count($parts) < 7 || !str_contains($parts[4], "query[")) {
        return MaybeO::of(NULL);
    }

    $src = $parts[7];
    $host = $parts[5];
    if (str_ends_with($host, "in-addr.arpa")) {
        return MaybeO::of(NULL);
    }

    return MaybeO::of(new Edge($src, $host, time()));
}

function tail_file($filePath, callable $fn) {
    $fileHandle = fopen($filePath, "r");
    if (!$fileHandle) {
        die("Error: Unable to open file: $filePath\n");
    }

    fseek($fileHandle, 0, SEEK_END);

    $lastPosition = ftell($fileHandle);

    while (true) {
        $readStreams = [$fileHandle];
        $writeStreams = $exceptStreams = null;

        // Wait for data to be available
        if (stream_select($readStreams, $writeStreams, $exceptStreams, 1)) {
            while (($line = fgets($fileHandle)) !== false) {
                $fn($line);
            }

            $lastPosition = ftell($fileHandle);
            //usleep(10000); // Sleep for 10ms

        } else {
            // Check for truncation
            clearstatcache();
            if (filesize($filePath) < $lastPosition) {
                echo "File truncated, restarting...\n";
                rewind($fileHandle);
                $lastPosition = 0;
            }
            // nothing happening, avoid any possibility for busy loop
            usleep(100000); // Sleep for 200ms
        }
    }

    fclose($fileHandle);
}

$config = json_decode(file_get_contents("config.json"), true);
panic_if(not(is_array($config)), "Unable to parse config.json, copy config.sample to config.json and configure settings.");




/*
$config = json_decode(file_get_contents("config.json"));
panic_if(not(is_array($config)), "Unable to parse config.json, copy config.sample to config.json and update");
*/

$db = DB::connect($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
panic_if(not($db->connected()), "Unable to connect to db");



    

/*
// Ensure the pipe exists and is a named pipe
if (!file_exists($config['dnsmasq_log'])) {
    echo "dnsmasq fifo does not exist " . $config['dnsmasq_log'] . "\n";
    posix_mkfifo($config['dnsmasq_log'], 0664);
}

// Open the named pipe for reading
$pipe = fopen($config['dnsmasq_log'], 'r');
panic_if(!$pipe, "Error: Unable to open named pipe {$config['dnsmasq_log']}.\n");
echo "Listening for input on the named pipe: {$config['dnsmasq_log']}\n";
*/

//$queue = MaybeO::of(ftok($config['dnsmasq_log'], 'R'))->map('msg_get_queue');

//print_r($queue);

$queue = MaybeO::of(msg_get_queue(ftok('config.json', 'R'), 0666));
//print_r($queue);
//die("\n");


$queue_send_fn = function(Edge $edge) use ($queue) {
    //echo " send edge\n";
    // print_r($edge);

    $error_code = 22;
    $success = msg_send($queue(), 1, json_encode($edge), false, false, $error_code);
    if (!$success) {
        $stat = msg_stat_queue($queue());
        echo "message send failed. number of queued messages: " . $stat['msg_qnum'];
        echo " PID of reading process: [" . $stat['msg_lrpid'] . "]\n";
    } else {
        echo " EDGE SENT!\n";
    }
};


try {
    tail_file($config['dnsmasq_log'], function (string $line) use ($queue_send_fn) {
        parse_line(trim($line))
            ->keep_if('not_azure')
            ->effect($queue_send_fn);
    });
} catch(Exception $e) {
    print_r($e);
}
die("complete\n");

/*
$host = "10.80.88.102";
$domain = "wrongdomain.com";
$edge = MaybeO::of(new Edge($host, $domain, time()));
print_r($edge);
$edge->effect($queue_send_fn);

die("sent edge\n");
*/

try {
    // Read the pipe line by line
    while (!feof($pipe)) {
        $line = fgets($pipe); // Read a single line
        if ($line !== false) {
            // Pass the line to the parsing function
            parse_line(trim($line))
                ->keep_if('not_azure')
                ->effect($queue_send_fn);
        }
    }
} finally {
    // Close the pipe when done
    fclose($pipe);
    echo "Closed the named pipe.\n";
}
