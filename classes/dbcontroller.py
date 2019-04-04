import sqlite3
import time
import os


class DBController:
    """This Class creates the database if none exist and provides methods to store and load Scan Results."""

    file_name = 'penscan.db'

    def __init__(self):
        """Checks if Database file exist, if not creates one."""
        exist = os.path.isfile(self.file_name)
        self.conn = sqlite3.connect(self.file_name)
        if not exist:
            self.create_database()
        pass

    def create_database(self):
        """Creates the Database-Tables."""
        c = self.conn.cursor()
        # Create table
        c.execute('''CREATE TABLE scans
                     (date text, host text, open_tcp text)''')
        # Save (commit) the changes
        self.conn.commit()

    def save_scan(self, host, ports_tcp):
        """Saves the Scan-Results to the Database

        Args:
            host (str)       : Host IP-Address
            ports_tcp (list) : List of TCP-Ports
        """
        c = self.conn.cursor()
        # Insert a row of data
        c.execute("INSERT INTO scans VALUES ('" + time.strftime("%x %X") + "', '" + host + "', '" +
                  self.list_to_string(ports_tcp) + "')")
        # Save (commit) the changes
        self.conn.commit()

    def load_scans(self):
        """Loads the previous scans.

        Return:
            ret (array) : Array of the Database Entries
        """
        ret = []
        for row in self.conn.execute("SELECT * from scans"):
            ret.insert(0, (row[0], row[1], self.string_to_list(row[2])))
        return ret

    @staticmethod
    def list_to_string(ports_list):
        """Converts the Port-List to a comma separated string.

        Args:
            ports_list (list) : The List of Ports

        Return:
            open_ports (str)  : String of opened Ports
        """
        if not ports_list:
            return ""

        open_ports = ""
        for key, value in ports_list.items():
            if value == 1:
                if open_ports == "":
                    open_ports += str(key)
                else:
                    open_ports += "," + str(key)
        return open_ports

    @staticmethod
    def string_to_list(port_string):
        """Converts the comma separated port string to a List

        Args:
            port_string (str) : String of opened Ports

        Return:
            port_list (list)  : The List of Ports
        """
        if port_string == '':
            return []

        # fills list with zeros
        port_list = {}
        for i in range(0, 65535):
            port_list[i] = 0

        # sets the value of the list with the corresponding port number to 1 (open)
        for item in port_string.split(','):
            port_list[int(item)] = 1

        return port_list
