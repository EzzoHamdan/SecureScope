# ioc_updater.py
import os
import re
from os import listdir
from os.path import isfile, join
import git
import pandas as pd
from git import rmtree

class IoCUpdater:
    """
    Downloads and parses threat intelligence IP blocklists into a CSV.
    """
    def __init__(self,
                 repo_url: str = "https://github.com/borestad/blocklist-abuseipdb.git",
                 local_dir: str = "./blocklist-abuseipdb/"):
        self.repo_url = repo_url
        self.local_dir = local_dir

    def update(self) -> None:
        print("Downloading IoC files...")
        # Clean old data if exists
        if os.path.isdir(self.local_dir):
            rmtree(self.local_dir)
        # Clone fresh
        git.Git(os.path.dirname(self.local_dir) or ".").clone(self.repo_url)
        ips = self._parse_ips()
        rmtree(self.local_dir)
        df = pd.DataFrame(ips, columns=["src_ip"])
        print(f"Parsed {len(ips)} IPs into DataFrame of shape {df.shape}")
        df.to_csv("Malicious_IP.csv", index=False)

    def _parse_ips(self) -> list[str]:
        files = [f for f in listdir(self.local_dir) if isfile(join(self.local_dir, f))]
        pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
        ips: list[str] = []
        for fname in files:
            path = join(self.local_dir, fname)
            # UTF-8 first, fallback to latin-1
            for encoding in ['utf-8', 'latin-1']:
                try:
                    with open(path, 'r', encoding=encoding) as fh:
                        for line in fh:
                            m = pattern.search(line)
                            if m:
                                ips.append(m.group(1))
                    break  
                except UnicodeDecodeError:
                    continue 
                except Exception as e:
                    print(f"Error reading {fname}: {e}")
                    break
        return ips