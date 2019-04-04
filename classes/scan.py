import socket
import threading
import select
import binascii

from classes.rawscan import RawScan


class Scan:
    """This class provides the methods to scan the target."""

    threads = []        # To perform threading
    output = {}         # For printing purposes
    portList = []
    SUCCESS = 0         # Success constant

    # Limiting access of semaphore
    threadLimiter = threading.BoundedSemaphore(100)

    def __init__(self, ports, ip):
        """Initializes Scan-Class with Port-Range and IP-Address.

        Args:
            ports (str) : Port or Port-Range to scan
            ip (str) : IP-Address to scan
        """

        # Get host from address. If address is given it does nothing
        self.ip = socket.gethostbyname(ip)

        # If range is given then save range in array
        if "-" in ports:
            for port in range(int(ports.split("-")[0]), int(ports.split("-")[1])+1):
                self.portList.append(port)
        elif "," in ports:
            for port in ports.split(','):
                self.portList.append(int(port))
        else:
            self.portList.append(int(ports))

    def scan_tcp(self):
        """Starts the multi-threaded TCP-Scan.
        For every thread a port number is passed and the thread get started.
        If there are too many threads started asynchronously,
        they will be enqueued and completed one by one.

        Returns:
            output: Array of opened ports
        """

        # Resetting the fields
        self.threads = []
        self.output = {}

        for i in self.portList:
            t = threading.Thread(target=self.connect_tcp, args=(i,))
            t.start()
            # Appending to hold reference
            self.threads.append(t)

        # Waiting to be finished
        for t in self.threads:
            t.join()

        return self.output

    def connect_tcp(self, port_number):
        """Performs the actual TCP-Scan.
        Limit the access of the resource by mutexing the output array with the threadLimiter.
        The socket gets created and binded. The open ports will be written into the output array
        for return into main function.

        Args:
            port_number (int) : The Port number
        """

        self.threadLimiter.acquire()
        try:
            # Creation of the socket
            tcp_sock = socket.socket(socket.AF_INET,      # IPv4
                                     socket.SOCK_STREAM)  # TCP

            # Sets the timeout for the socket
            tcp_sock.settimeout(0.5)

            # Like connect(address), but return an error indicator instead
            # of raising an exception for errors returned by the C-level connect()
            connected = tcp_sock.connect_ex((self.ip, port_number)) is self.SUCCESS
            if connected:
                self.output[port_number] = 1
            else:
                self.output[port_number] = 0

            # Close the socket
            tcp_sock.close()
        finally:
            self.threadLimiter.release()

    def scan_syn(self):
        """Starts the SYN Raw-Scan.
        Because of the not thread safe raw socket library the scans get
        started synchronously.

        Returns:
            output: Array of opened ports
        """

        # Resetting the fields
        self.output = {}

        for i in self.portList:
            self.connect_syn(i)

        return self.output

    def connect_syn(self, port_number):
        """Creation of the socket and reception of the raw packet.
        The socket get created and binded locally. With the multiplexing I/O module "select" the
        socket gets into receiving mode for our response (SYN ACK).

        Args:
            port_number (int) : Number of the port to scan

        """

        # Give necessary information to RawScan class
        rs = RawScan(self.ip)

        # Initialization of socket in IPv4, Raw Socket, TCP Mode
        syn_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        # Set IP Headers and for Raw Sockets IP_HDRINCL is necessary
        syn_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Bind the socket to address
        syn_sock.bind(('0.0.0.0', 12345))

        # Send, socket should not be connected
        syn_sock.sendto(rs.create_packet(port_number), (self.ip, port_number))

        # readable, writeable, error, 0.5 sec timeout
        r, _, _ = select.select([syn_sock], [], [], 0.5)
        if r:
            response = syn_sock.recv(1024)
            self.check_if_open(response)

        # Close the socket
        syn_sock.close()

    def check_if_open(self, response):
        """Checks if the port is open.
        By reading the flags on the correct position and also reading out the port_number.
        If the port is open, it will be written in the output array.

        Args:
            response (str) : The response from the receiving socket
        """
        cont = binascii.hexlify(response)
        port_number = int(cont[40:44], 16)
        # (012 = [SYN ACK])
        if cont[65:68] == b"012":
            self.output[port_number] = 1
        # else:
        # self.output[port_number] = 0
