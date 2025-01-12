<?php

define('MAX_BUCKETS', 2016); 
enum NodeType: string {
    case Host = 'Host';
    case Domain = 'Domain';
    case Exec = 'Exec';
    case File = 'File';
}

class Node {
    public int $id;
    public string $name;
    public NodeType $type;
}

class Process extends Node implements JsonSerializable {
    public int $pid;
    public string $arguments;
    public function jsonSerialize(): mixed {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'type' => $this->type,
            'pid' => $this->pid,
            'arguments' => $this->arguments,
        ];
    }
}

class Connect extends Node implements JsonSerializable {
    public int $port;
    public int $proto;
    public function jsonSerialize(): mixed {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'type' => $this->type,
            'port' => $this->port,
            'proto' => $this->proto,
        ];
    }
}

class Host extends Node implements JsonSerializable {
    public string $ip;
    public string $mac = "0";

    public function jsonSerialize(): mixed {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'type' => $this->type,
            'ip' => $this->ip,
            'mac' => $this->mac,
        ];
    }
}

class Edge implements JsonSerializable {
    public NodeType $srcType;
    public NodeType $dstType;
    private array $count;
    public int $src_id;
    public int $dst_id;

    public function __construct() {
        $this->count = array_fill(0, MAX_BUCKETS, 0);//pack("C*", ...array_fill(0, 2016, 0));
    }

    public function inc(int $min) {
        //$v = ord($this->count[$min]);
        $this->count[$min]++;
        //$v2 = ord($this->count[$min]);
    }

    public function jsonSerialize(): mixed {
        $ctr = [0,0,0,0,0,0,0];
        for ($i = 0; $i < MAX_BUCKETS; $i++) {
            $day = floor($i / 288);
            $ctr[$day] += $this->count[$i];
        }
        return [
            'srcType' => $this->srcType,
            'dstType' => $this->dstType,
            'ctr' => $ctr,
            'src_id' => $this->src_id,
            'dst_id' => $this->dst_id,
        ];
    }
}

function parse_cef(string $line) {
    echo "PARSE: [$line]\n";
    $parts = explode("|", $line);
    if (count($parts) < 8) {
        return [];
    }
    $extensions = explode('" "', $parts[7]);
    //print_r($parts);
    //print_r($extensions);
    $cef = ['cat' => $parts[4], 'type' => $parts[5], 'severity' => $parts[6]];
    foreach ($extensions as $part) {
        $kv = explode("=", trim($part, '"'));
        if (count($kv) != 2) {
            echo "malformed extension: [$part]\n";
            continue;
        }
        $cef[$kv[0]] = $kv[1];
    }
    //print_r($cef);


    return $cef;
}

// get an already open file handle or open a new one
function get_file_handle(string $host, string $type, bool $clear = false) {
    static $cache = [];
    static $age = [];

    // create the directory and log file if it doesn't exist
    $dir = "archive/{$host}";
    if (!is_dir($dir)) {
        mkdir($dir, 0750, true);
    }
    $file = "{$dir}/{$type}.log";

    // close the file handle if we are clearing the cache
    if ($clear && isset($cache[$file])) {
        @fclose($cache[$file]);
        unset($cache[$file]);
        unset($age[$file]);
    }

    
    // if the file handle is in the cache, return it
    if (isset($cache[$file]) && $age[$file] > time() - 300) {
        $age[$file] = time();
        return $cache[$file];
    }

    // open the file and add it to the file cache
    $cache[$file] = fopen($file, "a");
    $age[$file] = time();

    return $cache[$file];
}

function handle_cef(string $content, string $remote_ip, $queue) : mixed {
    // parse the input as CEF

    $cef = parse_cef($content);

    // send to c++ for anomaly detection 
    $success = false;
    if ($queue !== false) {
        $success = msg_send($queue, 1, json_encode($cef), false, false, $error_code);
    }
    if ($success === false) {
        $queue = msg_get_queue(ftok('config.json', 'R'), 0666);
    }

    // make sure we have all required fields
    if (!isset($cef['sHost'])) {
        $cef['sHost'] = "unknown";
    }
    if (!isset($cef['type'])) {
        $cef['type'] = "unknown";
    }

    // get the log file
    $fh = get_file_handle($cef['sHost'], $cef['type']);
    if ($fh === NULL) {
        $fh = get_file_handle($cef['sHost'], $cef['type'], true);
    }

    // write the file to disk
    fwrite($fh, $content . "\n");

    data_store($cef, $remote_ip);

    return $queue;
}

function get_minute() {
    // Get the current Unix timestamp
    $timestamp = time();

    // Calculate the current day of the week (0 = Sunday, 6 = Saturday)
    $dayOfWeek = (int)date('w', $timestamp);

    // Calculate the current minute of the day
    $minuteOfDay = (int)date('H', $timestamp) * 60 + (int)date('i', $timestamp);

    // Calculate the total minute of the week
    $minuteOfWeek = $dayOfWeek * 1440 + $minuteOfDay;

    return $minuteOfWeek % MAX_BUCKETS;
}


function data_store(array $cef, string $remote_ip) : mixed{
    static $nodes = [];
    static $edges = [];
    if (!isset($cef['type'])) {
        echo "DUMP!\n";
        return [$nodes, $edges];
    }

    $src_node_key = $cef['type'] . "-" . $cef['sHost'];
    $edge_key = "";



    if (isset($nodes[$cef['sHost']])) {
        $src_node = $nodes[$cef['sHost']];
    } else {
        $src_node = new Host();
        $src_node->name = $cef['sHost'];
        $src_node->type = NodeType::Host;
        $src_node->ip = $remote_ip;
        $src_node->id = count($nodes);

        echo "CREATE NODE: {$src_node->name}\n";
        $nodes[$cef['sHost']] = $src_node;
    }
    $edge_key .= $src_node->id . '-';

    if ($cef['type'] === "Exec") {
        $dst_node_key = "Exec-" . $cef['ppPath'];
        if (isset($nodes[$dst_node_key])) {
            $dst_node = $nodes[$dst_node_key];
        } else {
            $dst_node = new Process();
            $dst_node->type = NodeType::Exec;
            $dst_node->name = $cef['ppPath'];
            $dst_node->pid = $cef['spid'];
            $dst_node->arguments = $cef['arguments'];
            $dst_node->id = count($nodes);

            echo "CREATE EXEC NODE: {$dst_node->name}\n";
            $nodes[$dst_node_key] = $dst_node;
        }
    }
    $edge_key .= $dst_node->id;

    if (!isset($edges[$edge_key])) {
        $edge = new Edge();
        $edge->srcType = $src_node->type;
        $edge->dstType = $dst_node->type;
        $edge->src_id = $src_node->id;
        $edge->dst_id = $dst_node->id;
        echo "CREATE EDGE : {$edge_key}\n";
        $edges[$edge_key] = $edge;
    } else {
        $edge = $edges[$edge_key];
    }

    $min = get_minute();
    $edge->inc($min);
    $edges[$edge_key] = $edge;

    return [];
}



$server = new OpenSwoole\HTTP\Server("0.0.0.0", 10443, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);

$server->set([
    'reactor_num' => 2,
    'worker_num' => 4,
    'backlog' => 256,
    'dispatch_mode' => 2,    // fixed mode

    'max_request_execution_time' => 5,

    /*
    'open_http2_protocol' => true,
    */
    'open_http_protocol' => true,
    'daemonize' => 0,
    'user' => 'www-data',
    'group' => 'adm',
    'chroot' => '/opt/arp_assess',
    //'open_cpu_affinity' => true,
    //'cpu_affinity_ignore' => [0],
    'pid_file' => 'arp_assess.pid',

    // hot reload code
    'reload_async' => true,
    'max_wait_time' => 10,

    // TCP
    'max_conn' => 1024,
    'tcp_defer_accept' => 3,
    'open_tcp_keepalive' => 1,
    'heartbeat_idle_time' => 600,
    'heartbeat_check_interval' => 60,
    'enable_delay_receive' => true,
    'enable_reuse_port' => true,
    'enable_unsafe_event' => true,


    // Kernel
    'backlog' => 512,
    'kernel_socket_send_buffer_size' => 8192,
    'kernel_socket_recv_buffer_size' => 8192,

    // Coroutine
    'enable_coroutine' => true,
    'max_coroutine' => 3000,
    'send_yield' => true,

    // SSL
    'ssl_cert_file' => __DIR__ . '/certificates/server.crt',
    'ssl_key_file' => __DIR__ . '/certificates/server.key',
    'ssl_ciphers' => 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH',
    'ssl_protocols' => OpenSwoole\Constant::SSL_TLSv1_3 | OpenSwoole\Constant::SSL_TLSv1_2  | OpenSwoole\Constant::SSL_TLSv1_1,
    'ssl_verify_peer' => false,

]);

$server->on("Start", function (OpenSwoole\Http\Server $server) {
    echo "OpenSwoole http server is started at https://0.0.0.0:10443\n";
});

$queue = msg_get_queue(ftok('config.json', 'R'), 0666);
$server->on("Request", function (OpenSwoole\Http\Request $request, OpenSwoole\Http\Response $response) use ($queue) {
    echo "Request\n";

    $remote_ip = $request->server['remote_addr'];
    $content = $request->rawContent();
    if (substr($content, 0, 3) === "CEF") {
        echo "CEF\n";
        $queue = handle_cef($content, $remote_ip, $queue);

        $response->header("Content-Type", "text/plain");
        $response->end("OK\n");
    } else {
        echo "DUMP\n";
        $response->header("Content-Type", "text/javascript");
        $f = data_store([], $remote_ip);
        /*
        foreach ($f[1] as $key => $edge) {
            $x = json_encode($edge);
            //echo "[$x]\n";
        }
            */
        
        $x = json_encode($f, JSON_PRETTY_PRINT);
        //echo "ERR: " . json_last_error_msg(). "\n";
        //print_r($f);
        //echo "$x\n";
        $response->end("$x\n");
    }

    // report all is well
});

$server->start();
echo "FIN\n";