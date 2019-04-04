import os
import socket
import time

import click

from classes.scan import Scan
from classes.dbcontroller import DBController
from classes.configcontroller import ConfigController
from classes.services import Services


@click.command()
@click.option('-t', is_flag=True, help='Scan with TCP-Protocol')
@click.option('-s', is_flag=True, help='SYN Scan with TCP-Protocol')
@click.option('-l', is_flag=True, help='Log Scan-Results to DB')
@click.option('-f', type=click.STRING, help='Enter filepath where *.ini file is located for batch scanning')
@click.option('-ip', type=click.STRING, help='IP-Address/Hostname to scan')
@click.option('-r', type=click.STRING,
              help='Defines the Range(50-80) or a comma separated list(80,443) of ports to scan')
@click.option('-p', type=int, help='Prints the last X logged entries')
def main(t, s, l, f, ip, r, p):
    """PenScan - Port-Scanner written in Python to scan Hosts and exploit them afterwards."""

    if t is False and s is False and f is None and p is None:
        print("missing argument!\npenscan --help\tfor more information")
        quit(1)

    start_time = time.time()

    # config batch scanning was selected
    if f:
        # read the config
        config = ConfigController.read_config(f)
        # determines the scan type
        for item in config:
            if not item[1].find('syn'):
                s = True
                t = False
            if not item[1].find('tcp'):
                t = True
                s = False
            if not s and not t:
                print('Protocol ' + item[1] + ' unknown!')

            # set log flag
            if item[3] is 'yes':
                l = True
            else:
                l = False

            # run the scan
            scan(t, s, l, item[0], item[2])
            print('')
    # print saved scans from database
    if p:
        p = p+1
        controller = DBController()
        for item in controller.load_scans():
            if p > 1:
                print('Scan for ' + item[1] + ' Date: ' + item[0])
                print_ports(item[2], 'tcp')
                p = p-1
    # scan the selected target
    if not f and not p:
        scan(t, s, l, ip, r)

    # calculates the total time of the scans and prints it
    duration = time.time()-start_time
    print('Scan completed in ' + str(duration)[:4] + 's')


def scan(t, s, l, ip, r):
    """Initialises the necessary classes and starts the scans.

    Args:
        t (bool)    : Switch for TCP-Scan
        s (bool)    : Switch for SYN-Scan
        l (bool)    : Switch for Saving the Results to Database
        ip (str)    : The Host IP-Address
        r (str)     : The Port-Range
    """

    if ip is None and r is None:
        print('Argument: "ip" or "r" or both are missing')
        quit(2)

    controller = DBController()
    sc = Scan(r, ip)
    open_ports_tcp = {}
    # resolve the hostname if possible
    dns = socket.getfqdn(ip)
    if dns is not ip:
        print('Scan-Report for ' + dns + ' (' + ip + ')')
    else:
        print('Scan-Report for ' + dns)
    print('PORT\tSTATE\tSERVICE')

    # run tcp-scan on target
    if t:
        open_ports_tcp = sc.scan_tcp()
        print_ports(open_ports_tcp, 'tcp')
    # run syn-scan on target
    if s:
        # for syn-scan root permissions are needed
        if os.geteuid() == 0:
            open_ports_tcp = sc.scan_syn()
            print_ports(open_ports_tcp, 'tcp')
        else:
            print('Syn scan requires root privileges.')
            print('Doing nothing!')
    # save the scan results to database
    if l:
        controller.save_scan(ip, open_ports_tcp)


def print_ports(open_ports, protocol):
    """Prints the port-array formatted on the screen.

    Args:
        open_ports (list) : List of the opened ports of the host
        protocol (str)    : The protocol of the opened ports
    """
    if protocol == 'tcp':
        text = '\\tcp\topen\t'
    elif protocol == 'udp':
        text = '\\udp\topen\t'
    else:
        text = '\tprotocol unknown'

    # print all open ports
    if len(open_ports) > 0:
        for port, value in open_ports.items():
            if value == 1:
                print(str(port) + text + Services.get_service(port))


if __name__ == "__main__":
    """Entry-Point calls the main-Method."""
    main()
