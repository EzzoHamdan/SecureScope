import sys
from config import Config
from ioc_updater import IoCUpdater
from ids import IDS


def main():
    print("Welcome to the Network IDS tool")
    if len(sys.argv) < 2:
        print("Usage: python main.py <section>")
        sys.exit(1)

    section = sys.argv[1]
    config = Config(section=section)

    if config.ioc:
        updater = IoCUpdater()
        updater.update()

    if config.sniffing:
        ids = IDS(interface=config.nic,
                  check_offline=config.check_ioc_offline,
                  limit=config.packet_limit,
                  api_key="")
        ids.run()

if __name__ == "__main__":
    main()
