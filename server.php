<?php

system("killall -s 10 arp_assess");
sleep(1);
echo file_get_contents("netmap.json");
