# dovi-dhcp

Development setup:

Change to top level directory.

**run ryu application**: 
```console
$ python3 main.py
```
**start mininet topology**: 
```console
$ sudo mn --topo tree,2 --mac --switch ovsk,protocols=OpenFlow13 --controller=remote,port=3939
```


**How to run dhclient**:
```console
mininet> h1 dhclient h1-eth0 -v
```

**How to release an IP address**: 
```console
mininet> h1 dhclient h1-eth0 -r
```

**To access webpage**: 
```console
http://0.0.0.0:8080/dashboard
```
