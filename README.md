# connectcap

An https CONNECT proxy that records related outgoing
network traffic for diagnostics purposes.

The proxy is protected by RFC7616 digest authentication,
and outgoing traffic is recorded with libpcap for
subsequent analysis with tcpdump or wireshark.

Captures can be optionally emailed to the logged in user.

## what is it for?

Connectcap is designed to troubleshoot problems at the
network layer, rather than the layers above. If you have
a need to record traffic with tcpdump or wireshark, this
proxy will do that recording for you without the
hit-and-miss of running tcpdump by hand.

This allows you to find problems that may only be visible
on some parts of the internet and not others, caused by
issues such as broken MTU path discovery.

## downloads

Connectcap is available as RPMs through [COPR] as follows:

```
dnf copr enable minfrin/connectcap
dnf install connectcap
```

## example with local capture:

In the example below usernames and passwords are read
from /etc/connectcap/ccpasswd, and captures are saved
below /var/spool/connectcap.

Traffic is recorded on the interface enp0s3, which is
expected to have the src-ipv6-addr and src-ipv4-addr
IPv6 and IPv4 addresses respectively.

The proxy listens to all interfaces on port 5791.

```
connectdump -d /var/spool/connectcap \
	-p /etc/connectcap/ccpasswd \
	-6 src-ipv6-addr \
	-4 src-ipv4-addr \
	-i enp0s3 \
	-l 5791
```

## example with sendmail

In the example below, captures are delivered to sendmail
for onward delivery by email.

```
connectdump -d /var/spool/connectcap \
	-p /etc/connectcap/ccpasswd \
	-6 src-ipv6-addr \
	-4 src-ipv4-addr \
	-i enp0s3 \
	-l 5791 \
	/usr/sbin/sendmail -t
```

## how connectcap works

Before connecting to the origin server, connectcap preemptively
determines the source IP address and port of the outgoing TCP
connection, and sets up a packet capture for the source and
destination addresses.

Due to the quirks of this process, connectcap needs to be told
explicitly what the source IP addresses and ports are for
outgoing connections, in addition to the interface. Under
normal circumstances the TCP stack will choose these for you,
but will not tell you in advance what source address and port
will be chosen, not allowing you to start recording the TCP
connection ahead of time.

As a diagnostic tool, connectcap will make exactly one attempt
to contact each origin server, and will not attempt to fall
back or compensate for servers that are not working. This
allows problems to be visible that would otherwise be rendered
hidden by technologies like Happy Eyeballs.

## the ccpasswd file

Users are specified in the ccpasswd file as a username, a
password, and an email address, separated by colons.

```
username:atleastsixteencharacters:user@example.com
```

Passwords are stored in clear text, and to discourage password
reuse, password length is restricted to 16 characters or more.

The ccpasswd file must have no group or world permissions.

 [COPR]: <https://copr.fedorainfracloud.org/coprs/minfrin/connectcap/>
 
