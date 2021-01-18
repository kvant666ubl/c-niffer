<p align="center">
    <img src="https://img.icons8.com/color/452/lucifer.png"
        height="130">
</p>

<p align="center">
        <img src="https://img.shields.io/github/license/kvant666ubl/c-niffer" alt="License: GPL v3"></a>
        <img src="https://img.shields.io/github/forks/kvant666ubl/c-niffer" alt="forks"></a>
        <img src="https://img.shields.io/github/stars/kvant666ubl/c-niffer" alt="stars"></a>
        <img src="https://img.shields.io/github/issues/kvant666ubl/c-niffer" alt="issues"></a>
</p>


# c-niffer
A daemon that collects statistic about network traffic written in C using libpcap.

## Contents
- [Release](#release)
- [Installation](#installation)
  * [Install dependencies](#install-dependencies)
  * [Installation from source](#installation-from-source)
- [CLI](#cli)
  * [Flags](#flags)
      + [--start](#--start)
      + [--stop](#--stop)
      + [--show](#--show)
      + [--select](#--select)
      + [--stat](#--stat)
      + [--mode](#--mode)
      + [--help](#--help)
  * [Examples](#examples)
    + [Results example](#results-example)
    + [Wireless sniffing example](#wireless-sniffing-example)
    + [Wired sniffing example](#wired-sniffing-example)
  
## Release
A daemon would be implemented as a packet sniffer to capture data from a particular networking interface. Now it is daemon with CLI. It saves all of the incoming packets to the ```/var/log/syslog``` path for further analysis - it should giving all collected statistics for particular interface and print the number of packets received from ip address.


## Installation
### Install dependencies
Install libpcap framework for low-level network monitoring (cniffer is based on it)
```sh
$ sudo apt-get install libpcap-dev
```

### Installation from source
1. Using git to copy this repo to your local:
```sh
$ git clone https://github.com/kvant666ubl/c-niffer.git
```
2. Go to root of the cniffer repo. Compile and run with ```--help``` of ```-h``` option:
```sh
$ make all
$ sudo ./cniffer --help  
```
You must see the functional description and your personal available network devices like:
```
[MY AVAILABLE DEVICES]
1. wlp2s0 - (null)
2. any - Pseudo-device that captures on all interfaces
3. lo - (null)
4. enp1s0 - (null)
5. bluetooth0 - Bluetooth adapter number 0
6. nflog - Linux netfilter log (NFLOG) interface
7. nfqueue - Linux netfilter queue (NFQUEUE) interface
8. usbmon1 - USB bus number 1
9. usbmon2 - USB bus number 2
```
Note that: when you will run ./cniffer to start pcap loop - ```you need root privileges```.


## CLI
### flags
CLI is implemented with 7 flags: ```--start```, ```--stop```, ```--show```, ```--select```, ```--stat```, ```--mode``` and ```--help```.
### --start 
The packets with different protocol are being sniffed from ```--start``` call on from default network wired interface (eth0 e.g.). Deamon should handle signal from CLI ``` SIGCONT``` if it has stoped recently. 
### --stop
Capturing stopped. Deamon should handle signal from CLI (```SIGSTOP```).
### --show
Display in console number of packets received from some ip address, searching it in syslog file with time complexity ```log(N)``` for search.
### --select
Select network interface for sniffing available list can search in --help (eth0, wlan0, ethN, wlanN e.g.) from 1 to N (see dev-tab).
### --stat
Show all collected statistics for particular interface (see dev-tab).
### --mode
Allows to run with printable packets mode with printing on console. Option ```-P``` for printable output, default for None.
### --help
Usage information and examples.

## Examples
### Results example
When ***cniffer*** is working, all packages are writing in ```/var/log/syslog``` file with specific options. 
Here is an example of one TCP packet:
```
***********************TCP Packet*************************

Ethernet Header
   |-Destination Address : XX-XX-XX-XX-XX-XX 
   |-Source Address      : XX-XX-XX-XX-XX-XX 
   |-Protocol            : 8 

IP Header
   |-IP Version        : 4
   |-IP Header Length  : 5 DWORDS or 20 Bytes
   |-Type Of Service   : 0
   |-IP Total Length   : 157  Bytes(Size of Packet)
   |-Identification    : 49510
   |-TTL      : 56
   |-Protocol : 6
   |-Checksum : 22664
   |-Source IP        : 149.xxx.xxx.xx
   |-Destination IP   : 192.xxx.x.xxx

TCP Header
   |-Source Port      : 432
   |-Destination Port : 68531
   |-Sequence Number    : 2456252345
   |-Acknowledge Number : 7364252673
   |-Header Length      : 8 DWORDS or 32 BYTES
   |-Urgent Flag          : 0
   |-Acknowledgement Flag : 1
   |-Push Flag            : 1
   |-Reset Flag           : 0
   |-Synchronise Flag     : 0
   |-Finish Flag          : 0
   |-Window         : 32768
   |-Checksum       : 62556
   |-Urgent Pointer : 0

                        DATA Dump                         
IP Header
    F8 A2 D6 C7 8E B9 98 XX XX XX XX XX XX XX XX XX         .........Q....E.
    XX XX XX XX                                             XXXXXXXXXXXXXXXX
TCP Header
    40 00 38 06 83 17 95 9A XX XX XX XX XX XX XX XX         @.8......3...g..
    XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX         XXXXXXXXXXXXXXXX
Data Payload
    3B CC 12 33 E8 AC 8B 81 XX XX XX XX XX XX XX XX         ;..3....[.P.Q.50
    XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX         XXXXXXXXXXXXXXXX
    XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX         XXXXXXXXXXXXXXXX
    XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX         XXXXXXXXXXXXXXXX
    XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX         XXXXXXXXXXXXXXXX
    XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX         ....`2.D...@..>}
    XX XX XX XX XX XX XX XX XX                              ..p.4*Dl0

###########################################################
```
### Wireless sniffing example
We need select our wireless device, according to ***available devices***. Here, I use wlp2s0:
```sh
# ./cniffer --select 1
```
Results are logging now. If you want to see how it changing:
```sh
$ tail -f -n 20 /var/log/syslog
```

### Wired sniffing example
Simply run this line to snif your eth0 or enp1s0 e.g.:
```sh
# ./cniffer --start 
```
