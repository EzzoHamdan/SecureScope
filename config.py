# config.py
import configparser

class Config:
    """
    Loads and provides typed access to configuration parameters.
    """
    def __init__(self, config_file: str = "Conf.conf", section: str = "params"):
        parser = configparser.ConfigParser()
        parser.read(config_file)
        if section not in parser:
            raise KeyError(f"Section '{section}' not found in {config_file}")
        self._params = parser[section]

    @property
    def sniffing(self) -> bool:
        return self._params.getboolean("sniffing", fallback=False)

    @property
    def nic(self) -> str:
        return self._params.get("NIC", fallback="")

    @property
    def ioc(self) -> bool:
        return self._params.getboolean("IoC", fallback=False)

    @property
    def check_ioc_offline(self) -> bool:
        # True = offline, False = online
        return self._params.getboolean("check_ioc", fallback=True)
    
    @property
    def packet_limit(self) -> int:
        return self._params.getint("packet_limit", fallback=100)
