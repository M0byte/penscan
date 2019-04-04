import configparser


class ConfigController:
    """This class controls the handling of the config file."""

    def __init__(self):
        pass

    @staticmethod
    def read_config(filepath):
        """Reads the config file into the program.
        With the passed filepath to the *.ini config file, the content will be read in and
        the given values will proceeded internally.

        Args:
            filepath (str) : path to the config file

        Returns:
            output (2d array) : array with the values of the config file
        """
        output = []
        config = configparser.ConfigParser()
        config.read(filepath)

        for index, item in enumerate(config.sections()):
            output.append((config[item]['host'], config[item]['protocol'], config[item]['ports'], config[item]['log']))

        return output
