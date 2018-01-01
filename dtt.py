# Author: Akbar Qureshi	
#This script extracts sub domains longer than 40 characters from a PCAP file
import pyshark
import sys
import tldextract
import configparser

#Read sub domain length from config.ini
config = configparser.ConfigParser()
config.read('config.ini')
sd_length=config['DEFAULT']['SUB_DOMAIN_LENGTH']


if len(sys.argv) < 2:
    sys.exit('Usage: %s pcap-file' % sys.argv[0])


cap = pyshark.FileCapture(input_file=sys.argv[1], keep_packets=False,display_filter='udp.dstport==53 || tcp.dstport==53')
for pkt in cap:
	try:
            	dns = pkt.dns.qry_name
	    	sub_domain=tldextract.extract(dns)[0]
		if len(sub_domain) > int(sd_length):
			print "SRC_IP: {} >> DNS_QUERY: {} (SUB_DOMAIN_LENGTH:{})".format(pkt.ip.src,dns,str(len(sub_domain)))
        except AttributeError:
            	pass

	

