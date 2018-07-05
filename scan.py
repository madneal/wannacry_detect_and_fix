from optparse import OptionParser
from ipaddr import IPv4Network
import sys
import multiprocessing
import socket
from impacket

def parse_options():
    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option('-t', '--timeout', dest='timeout', default=0.5,
                      help="timeout in seconds, default 0.5")
    parser.add_option('-n', '--network', dest='network',
                      help="The scan network or host"
                           "192.168.0.100 for single host"
                           "192.168.0.100/24 for a network")
    options = parser.parse_args()[0]
    message = "Wannacry Scanner" \
              "Author: Bing Dong"
    print(message)
    if options.network is None:
        parser.print_help()
        sys.exit()
    return options

def scan(host):
    try:
        s = socket.create_connection((host, 445), timeout=timeout)
        if s is None:
            return
        cs = smb.SMB()

def run():
    options = parse_options()
    scan_network = options.network
    hosts = []

    if '/' in scan_network:
        network = IPv4Network(scan_network)
        for host in network.iterhosts():
            hosts.append(host)
        print('start to scan network {} for {} hosts...'.format(str(network), len(hosts)))
        pool = multiprocessing.Pool(processes=8)
        pool.map(scan, hosts)
        pool.close()
        pool.join()
    else:
        print('star to scan host {}'.format_map(scan_network))
        scan(scan_network)




if __name__ == '__main__':
    timeout = 0.5
    run()