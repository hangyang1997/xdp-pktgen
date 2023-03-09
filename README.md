### XDP PKTGEN

xdp pktgen tx 79233 pkts in 1s
```
 ./xpkt --dmac 08:00:27:99:1b:3f --smac 08:00:27:db:19:cf --dport 1000 -d 192.168.1.184 -s 192.168.1.200-192.168.1.201 --interface enp0s3 -q 0:0 --time 1 -l 64
Time consuming 0h:0m:1s :
Xpktgen ifname enp0s3:
tx               : 79233
rx               : 0
rx drop          : 0
tx invalid descs : 0
```

iperf3 tx 2048 pkts in 1s
```
iperf3 -c 192.168.1.184 -u -t1 -l 64 -Z
Connecting to host 192.168.1.184, port 5201
[  5] local 192.168.1.200 port 45672 connected to 192.168.1.184 port 5201
[ ID] Interval           Transfer     Bitrate         Total Datagrams
[  5]   0.00-1.00   sec   128 KBytes  1.05 Mbits/sec  2048
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-1.00   sec   128 KBytes  1.05 Mbits/sec  0.000 ms  0/2048 (0%)  sender
[  5]   0.00-1.00   sec   128 KBytes  1.05 Mbits/sec  0.040 ms  0/2048 (0%)  receiver

iperf Done.
```