# Dns Tunnel Detect

**Description**

The script extracts sub domains longer than 40 characters from a PCAP file. The output can assist analysts in detecting possible DNS tunneling where data is encoded into subdomains.

**Requirements**
* Python 2.7
* pyshark==0.3.7.11
* tldextract==2.2.0

**Screenshot**

The following screenshot shows the string **adminpassswordisPA55W0RD** endoed as hex into a sub domain.
![alt tag](https://github.com/akbarq/dns_tunnel_detect/blob/master/screenshot/img.png)

