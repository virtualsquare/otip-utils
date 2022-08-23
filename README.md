# otip-utils
One Time IP address (OTIP) utilities

OTIP means that the current IP address of a server changes periodically to
prevent networking attacks. This method has been designed for IPv6
networks. The current IP address of a server is computed on the basis of some
private information shared by legitimate users and the server itself, like a
password, and the current time.

`otip-utils` implements the following commands:

* `otipaddr`: computes the current OTIP address.
* `hashaddr`: computes the hash based address.
* `otip_rproxy`: a OTIP enabled reverse proxy. This tool permit to protect
TCP or UTP servers using OTIP.

### Acknowledgements
Thanks to Federico De Marchi who implemented an early prototype of
OTIP reverse proxy.

## How to install

`otip-utils`  depends on the following libraries, that must be installed in advance:

* [libstropt](https://github.com/rd235/libstropt)
* [libioth](https://github.com/virtualsquare/libioth)
* [iothconf](https://github.com/virtualsquare/iothconf)
* [iothdns](https://github.com/virtualsquare/iothdns)

`otip-utils` uses the cmake building system.
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

## `otipaddr`

`otipaddr` computes the current OTIP address (see also [iothnamed](https://github.com/virtualsquare/iothnamed) ).

example:

```
$ otipaddr test.otip.v2.cs.unibo.it secret_password
fd00:add1:5ea7:4a11:78e4:bb37:f7bf:f2cf
```

If you test this command you will get a different address. The trailing 64 bits of the address
are the result of a hash function computed on:

* the fully qualified domain name `test.otip.v2.cs.unibo.it`
* the passwd: `secret_password`
* the result of the integer devision between the current number of seconds from the eepoch (1970-01-01 00:00:00 +0000 UTC)
and the OTIP period (the default value is 32 seconds).

The base address (`otip.v2.cs.unibo.it` in the example above) defines the heading 64 bits of the address.

The usage of this command is:
```
Usage: otipaddr OPTIONS name password
        OPTIONS:
        --base|--baseaddr|-b <IPv6 base address or base addr domain name>
        --dnsstack|-s <ioth_stack_conf>
        --dns|-D <dnsaddr>
        --period|-T <ioth_period>
        --help|-h
```

* `name` is the fully qualified domain name of the required server.
* `passowrd` is the secret password.
* `--base|--baseaddr|-b <IPv6 base address or base addr domain name>`: set the base address. The argument
is an IPv6 address or a domain name. When this option is not included in the command line, the first component
of `name` (before the first dot) is taken as hostname while the remaining part of `name` (following the first dot)
is considered to be the domain name and queried to take the base address for OTIP computation.
* `--dns|-D <dnsaddr>` is the address of the dns to use. (use resolv.conf defs otherwise)
* `--dnsstack|-s <ioth_stack_conf>` this is the IoTh stack to use, `ioth_stack_conf` syntax is that defined for
`ioth_newstackc` in [iothconf](https://github.com/virtualsquare/iothconf).
* `--period|-T <ioth_period>` it the OTIP period in seconds (default value 32).

## hashaddr

`otipaddr` computes the hash based address. (see also [iothnamed](https://github.com/virtualsquare/iothnamed) ).

example:

```
$hashaddr -b fc00:: hash.test.local
fc00::f4b7:a5a9:259b:fb70
```

The usage of this command is:
```
Usage: hashaddr OPTIONS name
        OPTIONS:
        --base|--baseaddr|-b <IPv6 base address or base addr domain name>
        --dnsstack|-s <ioth_stack_conf>
        --dns|-D <dnsaddr>
        --help|-h
```

All the options have the same meaning of those described for otipaddr here above.

## `otip_rproxy`

`otip_rproxy` is a OTIP enabled reverse proxy. This tool permit to protect
TCP or UTP servers using OTIP.

```
+-------------+                   +-------------+
| real hidden | (*)               |             | (#)
| TCP or UDP  | <- hidden net ->  | otip_rproxy | <- the Internet
|   server    |                   |             |
+-------------+                   +-------------+

(*) hidden fixed IP address unreachable from the Internet
(#) public dynamic IP address. The address changes each "period" seconds (default value 32)
```

### command syntax

```
Usage: otip_rproxy OPTIONS
```
OPTIONS:

* `--rcfile|-f <conffile>` define the configuration file. The syntax
is described here below in the next section.
* `--daemon|-d` run `otip_rproxy` in background as a daemon. This option is often used together with `--pidfile|-p <pidfile>`
 to store the actual process id of the deamon.
* `--extstack|-e <ioth_extstack_conf>` define the TCP-IP stack used on the "public" side (#) in the picture above.
`ioth_extstack_conf` has the syntax defined for `ioth_newstackc` in [iothconf](https://github.com/virtualsquare/iothconf),
limited to the fags `stack`, `vnl` and `iface`.
* `--intstack|-i <ioth_stack_conf>` define the TCP-IP stack used on the "private" side (\*) in the picture above.
`ioth_stack_conf` has the syntax defined for `ioth_newstackc` in [iothconf](https://github.com/virtualsquare/iothconf).
The kernel stack is used if this option is omitted.
* `--name|-n <fully qualified name>` define the fully qualified domain name of the OTIP server
* `--base|--baseaddr|-b <base address>` define tha base address (IP address or domain name).
* `--passwd|-P <password>` define the secret password
* `--dns|-D <dnsaddr>` define the IP address of the DNS server
* `--udp|-u <extport>,<intaddr>,<intport>` UDP proxy definition, port as seen by clients, fixed IP address of the server,
server side port. The command can include several `--udp` options (for multiple UDP proxy services) .
* `--tcp|-t <extport>,<intaddr>,<intport>` TCP proxy definition, port as seen by clients, fixed IP address of the server,
server side port. The command can include several `--tcp` options (for multiple TCP proxy services) .
* `--otip_period <period>` OTIP period (default = 32 seconds)
* `--otip_postactive <seconds>` pre-activation time: in advance activation (to support negative drifts of clients' clocks)
* `--otip_preactive <seconds>` post-activation time: delayed deactivation (to support positive drifts of clients' clocks)
* `--tcp_listen_backlog <backlog>` tcp listen(2) argument
* `--tcp_timeout <seconds>` timeout to drop tcp idle connections
* `--udp_timeout <seconds>` timeout to drop udp reply map



### configuration file syntax

The configuration file loaded using the option `-f` or `--rcfile` has the following syntax:

* lines beginning by '#' are comments.
* the other lines have a tag and may have an argument if required by the tag.
The tags have the same name of the long options (`--something`) of the command line, their arguments
have the same syntax and meaning of each equivalent command line option.
Command line arguments have priority on the configuration file specifications:
if the same tag is specified as a command line option and in the configuration file, the value
in the command line is taken and the other ignored.
`udp` and `tcp` can appear several times in the configuration file.

```
        daemon
        pidfile  <pidfile>
        extstack <ioth_extstack_conf>
        intstack <ioth_stack_conf>
        name     <fully qualified name>
        base     <base address>
        passwd   <password>
        dns      <dnsaddr>
        udp      <extport>,<intaddr>,<intport>
        tcp      <extport>,<intaddr>,<intport>
        otip_period        <period>
        otip_postactive    <seconds>
        otip_preactive     <seconds>
        tcp_listen_backlog <backlog>
        tcp_timeout        <seconds>
        udp_timeout        <seconds>

```

### example

In a terminal window start a vde network (for example a hub).
```
$ vde_plug null:// hub:///tmp/hub
```

In a second terminal window start the proxy server using the test configuration file in
`example/otip_rproxy.rc`.
```
$ otip_rproxy -f otip_rproxy.rc
```
This example defines the otip server `renzo.otip` using base address  fc01:: password `mypassword`.
The udp port 4242 is forwarded to localhost (kernel stack) port 8484,
The tcp port 4242 is forwarded to localhost (kernel stack) port 8484,
and the tcp port 22 (i.e. ssh) is forwarded to port 22 of localhost.

In another terminal window start a vdens and test the configuration.
```
$ vdens /tmmp/hub
$ ip addr add fc01::1/64 dev vde0
$ ip link set vde0 up
$  ping -n `otipaddr -b fc01:: renzo.otip mypassword`
PING fc01::103b:2baf:8539:1e32(fc01::103b:2baf:8539:1e32) 56 data bytes
64 bytes from fc01::103b:2baf:8539:1e32: icmp_seq=1 ttl=64 time=0.734 ms
....
```
After some time (less than 40 secs) the ping ceases to reply... the address in no longer valid:
```
$  ping -n `otipaddr -b fc01:: renzo.otip mypassword`
PING fc01::18b5:b8a:5f15:3839(fc01::18b5:b8a:5f15:3839) 56 data bytes
64 bytes from fc01::18b5:b8a:5f15:3839: icmp_seq=1 ttl=64 time=0.757 ms
64 bytes from fc01::18b5:b8a:5f15:3839: icmp_seq=2 ttl=64 time=0.512 ms
...
```

The TCP forwarding can be tested using netcat.
In a shell (of the host, not inside the vdens) run a TCP server on port 8484 (IPv6!).
```
$ nc -6 -l -p 8484
```

Inside the vdens terminal window use netcat to connect a client to the server using an otip address:
```
$ nc `otipaddr -b fc01:: renzo.otip mypassword` 4242
```

any string typed on the client netcat is printed on the other nc and viceversa.

Another TCP forwarding example involves ssh.
In  the vdens terminal window type:
```
ssh `otipaddr -b fc01:: renzo.otip mypassword`
```

It is possible to test the forwarding of a UDP service.
Start a UDP server (for example `udp_echo.py`, a copy of [`1_14a_echo_server_udp.py`](https://github.com/PacktPublishing/Python-Network-Programming-Cookbook-Second-Edition/blob/master/Chapter01/1_14a_echo_server_udp.py) (MIT license), modified for IPV6).
In a shell (of the host, not inside the vdens) run a UDP server on port 8484 (IPv6!).`
```
$ python3 udp_echo.py --port 8484
```

In the vdens termian window the echo test can be experimented by the following command:
```
nc -u -6  `otipaddr -b fc01:: renzo.otip mypassword` 4242
```

### An example using `iothnamed`

Start the otip_rproxy as in the example above:
```
$ otip_rproxy -f otip_rproxy.rc
```

In another terminal start `iothnamed` using the configuration provided in the exmaple dir.
```
$ iothnamed  /tmp/iothnamed_otip.rc
```
This configuration provides a transparent name resolution using OTIP. `iothnamed` is connected to the vde
network `/tmp/hub`, ip address `fc01::24/64`.

Start a vdens configring the name server.
```
$ vdens -R fc01::24 vde:///tmp/hub
admin,net_raw# ping -n `otipaddr -b fc01:: renzo.otip mypassword`^C
# ip addr add fc01::1/64 dev vde0
# ip link set vde0 up
# ping -n renzo.otip
PING renzo.otip(fc01::801f:3538:9ba1:7101) 56 data bytes
64 bytes from fc01::801f:3538:9ba1:7101: icmp_seq=1 ttl=64 time=0.683 ms
64 bytes from fc01::801f:3538:9ba1:7101: icmp_seq=2 ttl=64 time=0.514 ms
64 bytes from fc01::801f:3538:9ba1:7101: icmp_seq=3 ttl=64 time=0.399 ms
```
after some time:
```
$ ping -n renzo.otip
PING renzo.otip(fc01::889:ccb8:ee7:5908) 56 data bytes
64 bytes from fc01::889:ccb8:ee7:5908: icmp_seq=1 ttl=64 time=0.372 ms
```

The OTIP address computation is done by `iothnamed`, so the command can use
otip addresses as if they were ordinary domain names.
```
$ ssh  renzo.otip
...
```

Note: otip_rproxy closes tcp idle connections after a timeout (default value: 120 seconds).
Long lasting tcp connections need keepalive protocols. e.g. for ssh:
```
$ ssh -o ServerAliveInterval=60 renzo.otip
```
