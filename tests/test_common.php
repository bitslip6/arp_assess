<?php
require dirname(__DIR__) . "/common.php";
require dirname(__DIR__) . "/threadfin/core.php";
require dirname(__DIR__) . "/threadfin/db.php";
define('BASE', dirname(__DIR__));

use const ThreadFin\DB\DB_DUPLICATE_IGNORE;
use const ThreadFin\DB\DB_DUPLICATE_UPDATE;
use const ThreadFin\DB\DB_FETCH_INSERT_ID;
use const ThreadFin\DB\DB_FETCH_NUM_ROWS;
use ThreadFin\DB\SQL as SQL;
use ThreadFin\DB\DB;

function test_example() {
    assert_true(true, "true is true");
}

function test_get_bucket_index() {
    $now = date('Y-m-d H:i:s', time());
    $dt1 = new DateTime($now);
    $bucket1 = get_bucket_index($dt1);
    assert_gt($bucket1, 0, "bucket mapped to 0 or negative time");
    assert_lt($bucket1, 2010, "bucket mapped to 0 or negative time");

    // skip ahead a week
    $now = date('Y-m-d H:i:s', time() + 86400 * 7);
    $dt2 = new DateTime($now);
    $bucket2 = get_bucket_index($dt2);
    assert_eq($bucket1, $bucket2, "weekly offsets should map to the same bucket!");

    $bucket3 = get_bucket_index(null);
    assert_eq($bucket3, 2010, "invalid bucket should return max+1");
}

function test_make_category_id() {

    $in = BASE . "/malware/categories.txt";
    $out = BASE . "/malware/categories.bak";
    rename($in, $out);

    $id = get_category_id('test', 'business', 0);
    assert_eq($id, 1, "category id creation failed");

    $id = get_category_id('test', 'business', 0);
    assert_eq($id, 1, "category id creation failed");

    $id = get_category_id('test', 'sports', 0);
    assert_eq($id, 2, "category id creation failed");

    $id = get_category_id('test', 'sports', 1);
    assert_eq($id, 1, "category id creation failed");

    if (file_exists($out)) {
        rename($out, $in);
    }
}

function test_alphamountain_category_id() {

    $in = BASE . "/malware/categories.txt";
    $out = BASE . "/malware/categories.bak";
    rename($in, $out);

    $id = get_category_id('test', 'business', 0);
    assert_eq($id, 1, "category id creation failed");

    $id = get_category_id('test', 'sports', $id);
    assert_eq($id, 1, "category id creation failed");

    $id = get_category_id('alphamountain.ai', 'pets', $id);
    assert_eq($id, 3, "alphamountain.ai override failed");

    if (file_exists($out)) {
        rename($out, $in);
    }
}

function test_mysql_read_bit_ops() {
    $config = json_decode(file_get_contents("config.json"), true);
    $db = DB::connect($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
    $edge_sql = $db->fetch("SELECT histogram, first, last FROM remote_edge WHERE local_id = {local_id} AND host_id = {host_id} AND dst_port = 443", ['local_id' => 9, 'host_id' => 40]);

    $histo = $edge_sql->col('histogram')();
    $result = setBit($histo, 3);
    assert_true(checkBit($histo, 3), "unable to set bit 3 in histogram");

    $histo = $edge_sql->col('histogram')();
    $result = unsetBit($result, 3);
    assert_false(checkBit($result, 3), "unable to clear bit 3 in histogram");
}

function test_mysql_write_bit_ops() {
    $local_id = 9;
    $remote_node_id = 40;
    $config = json_decode(file_get_contents("config.json"), true);
    $db = DB::connect($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
    $edge_sql = $db->fetch("SELECT histogram, first, last FROM remote_edge WHERE local_id = {local_id} AND host_id = {host_id} AND dst_port = 443", ['local_id' => 9, 'host_id' => 40]);

    
    $histo = $edge_sql->col('histogram')();
    $histo = clearRange($histo, 300, 400);

    $num_rows = $db->update("remote_edge", ['histogram' => $histo], ['local_id' => $local_id, 'host_id' => $remote_node_id, 'dst_port' => 443], DB_FETCH_NUM_ROWS);

    $edge_sql = $db->fetch("SELECT histogram, first, last FROM remote_edge WHERE local_id = {local_id} AND host_id = {host_id} AND dst_port = 443", ['local_id' => 9, 'host_id' => 40]);

    for($i = 300; $i < 400; $i++) {
        assert_false(checkBit($histo, $i), "bit $i is already set, should be clear!");
    }

    $result = setBit($histo, 333);
    assert_true(checkBit($histo, 333), "unable to set bit 333 in histogram");

    $num_rows = $db->update("remote_edge", ['histogram' => $result], ['local_id' => $local_id, 'host_id' => $remote_node_id, 'dst_port' => 443], DB_FETCH_NUM_ROWS);
    $edge_sql = $db->fetch("SELECT histogram, first, last FROM remote_edge WHERE local_id = {local_id} AND host_id = {host_id} AND dst_port = 443", ['local_id' => 9, 'host_id' => 40]);

    $histo = $edge_sql->col('histogram')();
    assert_true(checkBit($histo, 333), "unable to READ BACK set bit 333 in histogram from MySQL");
}