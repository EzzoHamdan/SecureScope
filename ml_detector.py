# ml_detector.py

import joblib
import pandas as pd

class MLDetector:
    def __init__(self, model_path: str = "ml_model.joblib", encoders_path: str = "label_encoders.joblib"):
        self.model = joblib.load(model_path)
        try:
            self.encoders = joblib.load(encoders_path)
        except FileNotFoundError:
            self.encoders = {}
            print("Warning: Label encoders not found")

    def predict_from_features(self, features_dict: dict) -> bool:
        """
        Returns True if malicious, False otherwise.
        """
        try:
            feature_mapping = {
                "Src Port": "spkts",           
                "Dst Port": "dpkts",           
                "Protocol": "proto",           
                "Flow Duration": "dur",
                "Total Fwd Packet": "spkts",
                "Total Bwd packets": "dpkts",
                "Fwd Packet Length Mean": "smean",
                "Bwd Packet Length Mean": "dmean",
                "Flow Bytes/s": "sbytes",
                "Flow Packets/s": "rate"
            }
            
            mapped_features = {}
            for new_name, old_name in feature_mapping.items():
                if old_name == "proto" and "proto" in self.encoders:
                    proto_str = "tcp" if features_dict[new_name] == 6 else "udp" 
                    try:
                        mapped_features[old_name] = self.encoders["proto"].transform([proto_str])[0]
                    except:
                        mapped_features[old_name] = 0
                elif old_name == "sbytes":  # Flow Bytes/s
                    mapped_features[old_name] = features_dict[new_name] / 3
                else:
                    mapped_features[old_name] = features_dict[new_name]
            
            # Calculate and adjust packet counts gap
            if "spkts" in mapped_features and "dpkts" in mapped_features:
                fwd_packets = mapped_features["spkts"]
                bwd_packets = mapped_features["dpkts"]
                gap = abs(fwd_packets - bwd_packets)
                half_gap = gap / 2
                
                # Reduce both by half the gap
                mapped_features["spkts"] = max(fwd_packets if fwd_packets == 0 else 5, fwd_packets - half_gap)
                mapped_features["dpkts"] = max(bwd_packets if bwd_packets == 0 else 5, bwd_packets - half_gap)

            if "service" in self.model.feature_names_in_:
                mapped_features["service"] = 0  
                
            row = pd.DataFrame([mapped_features], columns=self.model.feature_names_in_)
        
            prob = self.model.predict_proba(row)[0]
            #print(f"[MLDetector] Mal rate: {prob[1]}")
            return True if prob[1] > 0.61 else False  # threshold 
        except Exception as e:
            print(f"[MLDetector] Prediction failed: {e}")
            return False