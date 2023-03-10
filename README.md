### XDP PKTGEN

To develop and build, the kernel version is not lower than the following:
  - Ubuntu 20.04+

Build:
```bash
make -C libbpf/src
make
```

Usage
```doc
Base XDP packet gen

      --dmac=MAC             Dest Mac [required] x:x:x:x:x:x
      --dport=PORT           Destination port [required]
  -d, --dst=IP               Dest address [required] x.x.x.x
      --interface=IFNAME     [required]
  -l, --length=NUM           Data length [16-1400] Default=64
  -q, --queue-id=NUM:NUM     Correspondence between NIC queue and CPU Core,
                             exp: 0:1,1:2 [required] N:N,N:N...
      --smac=MAC             Source Mac [required] x:x:x:x:x:x
      --syn                  Send Tcp SYN, Default UDP
  -s, --src=IP-Range         IP range [required] x.x.x.x-x.x.x.x
      --time=SECOND          Run time (s)
  -?, --help                 Give this help list
      --usage                Give a short usage message
```
