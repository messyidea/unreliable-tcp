# unreliable-tcp

send raw tcp using libnet, receive tcp using libpcap.

#### [Warning] unstable, do not use it.

How to use it?
---
At first, you should install libnet and libpcap
```
apt-get install libnet1-dev
apt-get install libpcap0.8-dev
```
Then, just make.

```
./client device local_port remote_addr remote_port
# device is the network interface, like eth0
# local_port is the local port listening and receive udp date
# remote_addr is the ip of the server
# remote_port is the port of the server


./server device port backend_addr backend_port remote_addr remote_port
# port is the server listening ip, it equals to client(remote_port)
# backend_addr is the ip of the real udp server
# backend_port is the port of the real udp server
# remote_addr is the ip of client
# remote_port is the port of the client, it equals to client(local_port)
```

Tips
---
+ Now, for client, local_port should not equals to the remote_port.
+ Both client and server should not behind NAT.
