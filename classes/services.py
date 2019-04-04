class Services:
    """This class provides a method to resolve some services of ports"""

    @staticmethod
    def get_service(port):
        """Returns the service name to the corresponding port.

        Args:
                port (int) : port number

        Returns:
            service name (str) : Service name as string or empty string if service unknown
        """

        str_port = str(port)
        if str_port in Services.ports:
            return Services.ports[str_port]
        else:
            return ""

    ports = {'7': "echo",
             '9': "discard",
             '13': "daytime",
             '18': "message send",
             '20': "ftp data",
             '21': "ftp control",
             '22': "ssh",
             '23': "telnet",
             '25': "smtp",
             '37': "time",
             '43': "whois",
             '53': "domain",
             '69': "tftp",
             '80': "http",
             '88': "kerberos",
             '101': "nic host name",
             '107': "rtelnet",
             '109': "pop2",
             '110': "pop3",
             '115': "sftp",
             '118': "sql",
             '119': "nntp",
             '137': "netbios",
             '143': "imap",
             '152': "bftp",
             '156': "sql",
             '158': "dmsp",
             '170': "postscript",
             '177': "x server",
             '179': "bgp",
             '194': "irc",
             '220': "imap v3",
             '389': "ldap",
             '401': "ups",
             '443': "https",
             '445': "active directory / smb",
             '464': "kerberos change/set password",
             '514': "remote shell",
             '515': "ldp",
             '525': "timeserver",
             '543': "kerberos login",
             '544': "kerberos remote shell",
             '546': "dhcp v6 client",
             '547': "dhcp v6 server",
             '587': "smtp",
             '631': "ipp",
             '636': "ldaps",
             '666': "doom",
             '749': "kerberos administration",
             '873': "rsync",
             '989': "ftps data",
             '990': "ftps control",
             }
