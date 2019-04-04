import socket
from struct import *


class RawScan:
    """This class sets the necessary options to perform a stealth syn scan.
    By providing the helper functions for the syn scan and also setting the properties
    correctly, this class get called by the scan class.
    """

    # Initialize empty packets in byte format
    tcp_header = b""
    ip_header = b""
    packet = b""

    # Initialize all settings necessary for the ip header
    version = 0x4
    ihl = 0x5
    type_of_service = 0x0
    total_length = 0x28
    identification = 0xabcd
    flags = 0x0
    fragment_offset = 0x0
    ttl = 0x40
    protocol = 0x6
    header_checksum = 0x0
    src_ip = socket.gethostbyname(socket.getfqdn())

    # Putting version and ihl into one byte
    v_ihl = (version << 4) + ihl

    # Putting flags and fragment_offset into two byte
    f_fo = (flags << 13) + fragment_offset

    # TCP segment
    src_port = 0x3039  # 12345
    dest_port = 0      # initialize variable
    seq_no = 0x0
    ack_no = 0x0
    data_offset_flags = 0x5
    reserved = 0x0

    window_size = 0x7110
    checksum = 0x0
    urg_pointer = 0x0

    # Shifting bits for the data offset location
    data_offset = (data_offset_flags << 12) + (reserved << 9)

    ns, cwr, ece, urg, ack, psh, rst, syn, fin = 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0
    # Shifting bits for the flag location
    flags = (ns << 8) + (cwr << 7) + (ece << 6) + (urg << 5) \
                 + (ack << 4) + (psh << 3) + (rst << 2) + (syn << 1) + fin

    # Putting both together into two byte
    data_offset_flags = data_offset + flags

    def __init__(self, ip):
        """RawScan Constructor.
        Sets the values of the necessary properties.

        Args:
            ip (str)    : Ip of the target
        """

        self.dest_ip = ip

        # Converting from dotted-quad string into 32 bit packed binary
        self.src_addr = socket.inet_aton(self.src_ip)
        self.dest_addr = socket.inet_aton(ip)

    @staticmethod
    def calc_checksum(msg):
        """Calculation of the checksum.
        The checksum of the given argument will be calculated.
        In our case the ip and tcp header checksum will be made.
        IP + TCP Header Checksum consists of:
        1. Adding all values of the properties together
        2. Remove the Carryover (+0x0001)
        3. Negation with 0xffff

        Args:
            msg (str) : Network packet as string

        Returns:
            s (str) : Checksum of the network packet
        """
        # Adding all together
        s = 0
        # Byte packed values adding together
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w

        # Removing carryover by moving 4 bytes down then
        # do and conjunction with 4 bytes of 1's
        s = (s >> 16) + (s & 0xffff)

        # Negation
        # Complement of s and subtract from highest value
        s = ~s & 0xffff

        return s

    def create_ip_header(self):
        """Creation the whole ip packet.
        With the use of the pack function the temporary ip header will be created and returned.


        IP Header Format

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |Version|  IHL  |Type of Service|          Total Length         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         Identification        |Flags|      Fragment Offset    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Time to Live |    Protocol   |         Header Checksum       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                       Source Address                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    Destination Address                        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    Options                    |    Padding    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       https://tools.ietf.org/html/rfc791#page-11


        Returns:
            tmp_ip_header (str) : Temporary ip header
        """
        # !     network (= big-endian)
        # B     unsigned char 1 byte
        # H     unsigned short 2 byte
        # L     unsigned long 4 byte
        # 4s    char[] with length of 4

        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                             self.identification, self.f_fo,
                             self.ttl, self.protocol, self.header_checksum,
                             self.src_addr,
                             self.dest_addr)
        return tmp_ip_header

    def create_tcp_header(self):
        """Creation of the whole tcp packet.
        With the use of the pack function the temporary tcp header will be created and returned.


        TCP Header Format

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Source Port          |       Destination Port        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                        Sequence Number                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    Acknowledgment Number                      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Data |           |U|A|P|R|S|F|                               |
           | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
           |       |           |G|K|H|T|N|N|                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Checksum            |         Urgent Pointer        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    Options                    |    Padding    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                             data                              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

           https://tools.ietf.org/html/rfc793#page-15


        Returns:
            tmp_tcp_header (str) : Temporary tcp header
        """
        # !     network (= big-endian)
        # B     unsigned char 1 byte
        # H     unsigned short 2 byte
        # L     unsigned long 4 byte
        # 4s    char[] with length of 4

        tmp_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                              self.seq_no,
                              self.ack_no,
                              self.data_offset_flags, self.window_size,
                              self.checksum, self.urg_pointer)
        return tmp_tcp_header

    def create_packet(self, port_number):
        """Creation of the whole raw packet.
        The ip header and the tcp header get created and merged into one complete raw packet.

         Protocol Layering

                        +---------------------+
                        |     higher-level    |
                        +---------------------+
                  ->    |        TCP          |
                        +---------------------+
                  ->    |  internet protocol  |
                        +---------------------+
                        |communication network|
                        +---------------------+

                https://tools.ietf.org/html/rfc793#page-2


        Args:
            port_number (int) : Port number to send packet to

        Returns:
            final_header (str) : Final ip + tcp header
        """

        # !     network (= big-endian)
        # B     unsigned char 1 byte
        # H     unsigned short 2 byte
        # L     unsigned long 4 byte
        # 4s    char[] with length of 4

        # Setting port number
        self.dest_port = port_number

        # IP header creation with checksum from the temporary ip header
        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                               self.identification, self.f_fo,
                               self.ttl, self.protocol, self.calc_checksum(self.create_ip_header()),
                               self.src_addr,
                               self.dest_addr)

        # Temporary tcp header creation with checksum 0x0
        tmp_tcp_header = self.create_tcp_header()

        pseudo_header = pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol,
                             len(tmp_tcp_header))

        # Needed for tcp checksum calculation
        psh = pseudo_header + tmp_tcp_header

        # Creation of final tcp header with correct checksum
        final_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                self.seq_no,
                                self.ack_no,
                                self.data_offset_flags, self.window_size,
                                self.calc_checksum(psh), self.urg_pointer)

        self.ip_header = final_ip_header
        self.tcp_header = final_tcp_header

        # Putting both together and return
        return final_ip_header + final_tcp_header
