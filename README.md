### XDP PKTGEN

xdp pktgen tx 79233 pkts in 1s
```
 ./xpkt --dmac 08:00:27:99:1b:3f --smac 08:00:27:db:19:cf --dport 1000 -d 192.168.1.184 \
	-s 192.168.1.200-192.168.1.201 --interface enp0s3 -q 0:0 --time 1 -l 64
Time consuming 0h:0m:1s :
Xpktgen ifname enp0s3:
tx               : 79233
rx               : 0
rx drop          : 0
tx invalid descs : 0
```

iperf3 tx 32404 pkts in 1s
```
 iperf3 -c 192.168.1.184 -u -t1 -l 16 -Z -b 1G
Connecting to host 192.168.1.184, port 5201
[  5] local 192.168.1.200 port 37856 connected to 192.168.1.184 port 5201
[ ID] Interval           Transfer     Bitrate         Total Datagrams
[  5]   0.00-1.00   sec   506 KBytes  4.15 Mbits/sec  32404
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-1.00   sec   506 KBytes  4.15 Mbits/sec  0.000 ms  0/32404 (0%)  sender
[  5]   0.00-1.00   sec   504 KBytes  4.13 Mbits/sec  0.007 ms  0/32235 (0%)  receiver
```
