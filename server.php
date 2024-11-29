<?php

system("killall -s 10 arp_assess");
sleep(2);
echo file_get_contents("netmap.json");
