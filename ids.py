# ids.py
import pyshark
from pyshark.capture.capture import TSharkCrashException
from ip_checker import IPChecker
from ml_detector import MLDetector
import time
import ipaddress

class IDS:
    def __init__(self, interface: str, check_offline: bool = True, api_key: str | None = None,
                 timeout: float = 0.01, limit: int = 10):
        self.interface = interface
        self.timeout = timeout
        self.limit = limit
        self.checker = IPChecker(api_key=api_key)
        self.check_offline = check_offline
        self.ml_detector = MLDetector()
        self.flow_stats = {}

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private/internal"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    def run(self) -> None:
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            capture.sniff(timeout=self.timeout)
        except TSharkCrashException as e:
            print(f"TShark crashed: {e}")
            return
        
        try:
            processed_count = 0
            for packet in capture:
                info = self._extract_info(packet)
                src_ip = info.get('src_ip')
                dst_ip = info.get('dst_ip')
                if not src_ip:
                    continue
                
                # Skip private IPs before counting
                if self._is_private_ip(src_ip):
                    #print(f"[IDS] Skipping private IP: {src_ip}")
                    continue
                
                print(f"Packet_Number: {processed_count}")
                processed_count += 1
                
                if processed_count >= self.limit:
                    break
                
                # Check IP reputation
                if self.check_offline:
                    ip_is_malicious = self.checker.check_offline(src_ip)
                else:
                    ip_is_malicious = self.checker.check_online(src_ip)
                    
                flow_key = f"{src_ip}:{info.get('src_port', 0)}-{dst_ip}:{info.get('dst_port', 0)}"
                reverse_flow_key = f"{dst_ip}:{info.get('dst_port', 0)}-{src_ip}:{info.get('src_port', 0)}"
                
                if flow_key not in self.flow_stats:
                    self.flow_stats[flow_key] = {
                        'start_time': info.get('timestamp', time.time()),
                        'last_time': info.get('timestamp', time.time()),
                        'fwd_packets': 0,
                        'bwd_packets': 0,
                        'fwd_bytes': 0,
                        'bwd_bytes': 0
                    }
                
                current_time = info.get('timestamp', time.time())
                self.flow_stats[flow_key]['last_time'] = current_time
                self.flow_stats[flow_key]['fwd_packets'] += 1
                self.flow_stats[flow_key]['fwd_bytes'] += info.get('frame_len', 0)
                
                if reverse_flow_key in self.flow_stats:
                    self.flow_stats[reverse_flow_key]['bwd_packets'] += 1
                    self.flow_stats[reverse_flow_key]['bwd_bytes'] += info.get('frame_len', 0)
                
                flow_duration = self.flow_stats[flow_key]['last_time'] - self.flow_stats[flow_key]['start_time']
                flow_duration = max(flow_duration, 0.001)  
                
                features_dict = {
                    "Src Port": info.get("src_port", 0),
                    "Dst Port": info.get("dst_port", 0),
                    "Protocol": 6 if info.get("transport_layer") == "TCP" else 17,  # TCP/UDP
                    "Flow Duration": flow_duration,
                    "Total Fwd Packet": self.flow_stats[flow_key].get('fwd_packets', 10) if self.flow_stats[flow_key].get('fwd_packets', 0) > 0 else 10,
                    "Total Bwd packets": self.flow_stats[flow_key].get('bwd_packets', 5) if self.flow_stats[flow_key].get('bwd_packets', 0) > 0 else 5,
                    "Fwd Packet Length Mean": (self.flow_stats[flow_key]['fwd_bytes'] / 
                                              max(self.flow_stats[flow_key]['fwd_packets'], 1)),
                    "Bwd Packet Length Mean": (self.flow_stats[flow_key]['bwd_bytes'] / 
                                              max(self.flow_stats[flow_key]['bwd_packets'], 1)),
                    "Flow Bytes/s": (self.flow_stats[flow_key]['fwd_bytes'] + 
                                    self.flow_stats[flow_key].get('bwd_bytes', 0)) / flow_duration,
                    "Flow Packets/s": (self.flow_stats[flow_key]['fwd_packets'] + 
                                      self.flow_stats[flow_key].get('bwd_packets', 0)) / flow_duration
                }

                ml_is_malicious = self.ml_detector.predict_from_features(features_dict)
                
                # Check for consensus and print appropriate alerts
                if ml_is_malicious and ip_is_malicious:
                    print("\n" + "="*80)
                    print("🚨 CRITICAL THREAT DETECTED! 🚨")
                    print("="*80)
                    print(f"🔥 DOUBLE CONFIRMATION: IP {src_ip} is MALICIOUS! 🔥")
                    print("📊 ML Model: MALICIOUS ❌")
                    print("🌐 IP Reputation: MALICIOUS ❌")
                    print("⚠️  IMMEDIATE ACTION REQUIRED!")
                    print("="*80 + "\n")
                elif ml_is_malicious:
                    print(f"[MLDetector] ALERT!!! Detected malicious IP: {src_ip}")
                elif ip_is_malicious:
                    print(f"[IPChecker] ALERT!!! Detected malicious IP: {src_ip}")
        
        except Exception as e:
            print(f"Error during packet capture: {e}")
            return

    def _extract_info(self, packet) -> dict:
        info: dict = {}
        info['highest_layer'] = packet.highest_layer.upper()
        info['transport_layer'] = packet.transport_layer.upper() if packet.transport_layer else 'NONE'
        info['timestamp'] = int(float(packet.sniff_timestamp))
        info['frame_len'] = int(packet.length)
        for layer in packet.layers:
            lname = layer.layer_name.upper()
            if lname == 'ETH':
                info['mac_src'], info['mac_dst'] = layer.dst, layer.src
                info['eth_type'] = layer.type
            if lname in ('IP', 'IPV6'):
                info['src_ip'], info['dst_ip'] = layer.src, layer.dst
                info['geo_country'] = getattr(layer, 'geocountry', 'Unknown')
            elif lname == info['transport_layer']:
                info['src_port'], info['dst_port'] = int(layer.dstport), int(layer.srcport)
        return info