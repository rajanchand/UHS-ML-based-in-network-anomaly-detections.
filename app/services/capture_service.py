import time
import threading
import random
from queue import Queue, Empty
import numpy as np
import pandas as pd
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

class CaptureService:
    """
    Background network traffic capture service.
    Sniffs real packets using Scapy (with root privilege) or falls back to
    generating mock flows in non-root/sandbox environments.
    
    Processes captured packets into flows, extracts features, performs live
    ML prediction, and exposes a stream of telemetry data.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(CaptureService, cls).__new__(cls, *args, **kwargs)
                cls._instance._init_service()
            return cls._instance

    def _init_service(self):
        self.is_running = False
        self.thread = None
        self.telemetry_queue = Queue(maxsize=1000)
        self.recent_threats = []
        self.active_model = None
        self.preprocessor = None
        self.model_type = None
        self.dataset_id = None
        self.analysis_id = None
        self.features_list = ["duration", "protocol_type", "src_bytes", "dst_bytes", "wrong_fragment", "urgent", "hot", "num_failed_logins"]
        self.flow_store = {}  # Keep track of active flows for scapy extraction
        self.packets_count = 0
        self.anomalies_count = 0

    def start(self, model=None, preprocessor=None, model_type=None, dataset_id=None, analysis_id=None):
        """Start the background sniffing/generation thread."""
        with self._lock:
            if self.is_running:
                return
            
            self.active_model = model
            self.preprocessor = preprocessor
            self.model_type = model_type
            self.dataset_id = dataset_id
            self.analysis_id = analysis_id
            self.is_running = True
            
            # Reset counters
            self.packets_count = 0
            self.anomalies_count = 0
            self.flow_store.clear()
            
            self.thread = threading.Thread(target=self._run_capture, daemon=True)
            self.thread.start()
            print("[CAPTURE] Capture service started.")

    def stop(self):
        """Stop the background thread."""
        with self._lock:
            if not self.is_running:
                return
            self.is_running = False
            if self.thread:
                self.thread.join(timeout=1.0)
            print("[CAPTURE] Capture service stopped.")

    def set_model(self, model, preprocessor, model_type, dataset_id=None, analysis_id=None):
        """Dynamically update the active model used for live inference."""
        self.active_model = model
        self.preprocessor = preprocessor
        self.model_type = model_type
        self.dataset_id = dataset_id
        self.analysis_id = analysis_id
        print(f"[CAPTURE] Dynamic model updated to: {model_type} (Dataset: {dataset_id}, Analysis: {analysis_id})")

    def get_stream_generator(self):
        """Generates Server-Sent Events (SSE) from the telemetry queue."""
        while self.is_running:
            try:
                # Non-blocking fetch from queue
                data = self.telemetry_queue.get(timeout=1.5)
                yield f"data: {data}\n\n"
            except Empty:
                # Keep-alive ping
                yield ": ping\n\n"

    def _run_capture(self):
        """sniff thread loop."""
        use_mock = True
        
        if HAS_SCAPY:
            try:
                # Test sniff to check for permissions (requires root)
                sniff(count=1, timeout=0.1, store=False)
                use_mock = False
                print("[CAPTURE] Scapy sniff test passed. Using real sniffing.")
            except Exception as e:
                print(f"[CAPTURE] Scapy test failed (permission or driver issue): {e}. Falling back to Mock Generator.")

        if use_mock:
            self._run_mock_generator()
        else:
            self._run_scapy_sniffer()

    def _run_scapy_sniffer(self):
        """Uses scapy to sniff network packets in real-time."""
        def packet_handler(pkt):
            if not self.is_running:
                return
            
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = pkt[IP].proto
                size = len(pkt)
                
                # Protocol names mapping
                proto_name = 'tcp'
                if proto == 17: proto_name = 'udp'
                elif proto == 1: proto_name = 'icmp'
                
                flow_key = (src_ip, dst_ip, proto_name)
                now = time.time()
                
                # Aggregate packet into flow
                if flow_key not in self.flow_store:
                    self.flow_store[flow_key] = {
                        'start_time': now,
                        'last_time': now,
                        'src_bytes': size,
                        'dst_bytes': 0,
                        'packets': 1
                    }
                else:
                    flow = self.flow_store[flow_key]
                    flow['last_time'] = now
                    flow['src_bytes'] += size
                    flow['packets'] += 1

                self.packets_count += 1
                
                # Every 5 packets per flow, trigger model inference
                flow = self.flow_store[flow_key]
                if flow['packets'] % 5 == 0:
                    self._evaluate_flow(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        duration=flow['last_time'] - flow['start_time'],
                        proto=proto_name,
                        src_bytes=flow['src_bytes'],
                        dst_bytes=flow['dst_bytes']
                    )

        # Scapy sniffing loop
        sniff(prn=packet_handler, store=False, timeout=1.0)
        
        # Keep running sniffing in a loop as long as is_running is True
        while self.is_running:
            sniff(prn=packet_handler, store=False, timeout=1.0)

    def _run_mock_generator(self):
        """Generates realistic simulated network traffic when root capture is unavailable."""
        protocols = ['tcp', 'udp', 'icmp']
        threat_ips = ['192.168.1.105', '10.0.0.45', '185.220.101.4', '45.227.254.12']
        clean_ips = ['192.168.1.10', '192.168.1.22', '10.0.0.2', '10.0.0.8']
        
        while self.is_running:
            time.sleep(random.uniform(0.5, 2.0))
            
            # Determine if this mock flow is an attack flow (approx 15% probability)
            is_attack = random.random() < 0.15
            
            src_ip = random.choice(threat_ips) if is_attack else random.choice(clean_ips)
            dst_ip = '192.168.1.1'  # Server target
            proto = random.choice(protocols)
            
            if is_attack:
                # High traffic patterns typical of scans or flood attacks
                duration = random.uniform(0.0, 0.5)
                src_bytes = random.choice([0, 1024, 5000, 65535])
                dst_bytes = random.choice([0, 40])
                num_failed_logins = random.choice([0, 3, 5]) if proto == 'tcp' else 0
                hot_state = random.choice([0, 1])
            else:
                duration = random.uniform(0.1, 5.0)
                src_bytes = random.randint(40, 3000)
                dst_bytes = random.randint(100, 10000)
                num_failed_logins = 0
                hot_state = 0
                
            self.packets_count += random.randint(1, 10)
            self._evaluate_flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                duration=duration,
                proto=proto,
                src_bytes=src_bytes,
                dst_bytes=dst_bytes,
                num_failed_logins=num_failed_logins,
                hot=hot_state
            )

    def _evaluate_flow(self, src_ip, dst_ip, duration, proto, src_bytes, dst_bytes, num_failed_logins=0, hot=0):
        """Construct DataFrame of flow metrics, pre-process, predict, and stream result."""
        # Setup input row mapping
        flow_df = pd.DataFrame([{
            'duration': float(duration),
            'protocol_type': str(proto),
            'src_bytes': int(src_bytes),
            'dst_bytes': int(dst_bytes),
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': int(hot),
            'num_failed_logins': int(num_failed_logins)
        }])

        # Preprocess features safely
        X_scaled = None
        prediction = 0
        confidence = 0.5
        threat_score = 10.0
        
        if self.active_model and self.preprocessor and self.preprocessor.is_fitted:
            try:
                # Preprocess without target label
                X_scaled, _, _ = self.preprocessor.preprocess(flow_df, fit=False)
                
                # Perform model prediction
                preds = self.active_model.predict(X_scaled)
                prediction = int(preds[0])
                
                # Try to get prediction probability confidence
                try:
                    proba = self.active_model.predict_proba(X_scaled)
                    if len(proba.shape) > 1 and proba.shape[1] > 1:
                        # Multiclass
                        confidence = float(proba[0][prediction])
                        # Treat class 0 as Normal, sum of others as threat
                        anomaly_proba = proba[0][1:].sum()
                    else:
                        anomaly_proba = float(proba[0])
                        confidence = anomaly_proba if prediction == 1 else 1.0 - anomaly_proba
                    
                    threat_score = round(anomaly_proba * 100, 1)
                except Exception:
                    confidence = 1.0 if prediction == 1 else 0.0
                    threat_score = 90.0 if prediction == 1 else 10.0

            except Exception as e:
                print(f"[CAPTURE] Preprocessing/Inference failed: {e}")

        # Map labels to threat names
        class_names = {
            0: 'Normal',
            1: 'DDoS',
            2: 'DoS',
            3: 'Port Scan',
            4: 'Brute Force',
            5: 'Bot Attack'
        }
        threat_type = class_names.get(prediction, 'General Anomaly')
        
        if prediction > 0:
            self.anomalies_count += 1
            
        timestamp = datetime.now().strftime('%H:%M:%S')

        # Add threat details to recent list
        threat_record = {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'threat_type': threat_type,
            'prediction': prediction,
            'confidence': round(confidence * 100, 1),
            'threat_score': threat_score,
            'duration': round(duration, 3),
            'proto': proto.upper(),
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'dataset_id': self.dataset_id
        }

        if prediction > 0:
            self.recent_threats.insert(0, threat_record)
            if len(self.recent_threats) > 10:
                self.recent_threats.pop()

        # Build SSE response JSON
        import json
        stream_data = {
            'timestamp': timestamp,
            'packets_sec': int(self.packets_count),
            'anomalies_found': int(self.anomalies_count),
            'recent_threat': threat_record if prediction > 0 else None,
            'model_type': self.model_type or 'None Active',
            'analysis_id': self.analysis_id
        }
        
        # Reset counters periodically to behave like "packets/sec"
        self.packets_count = 0
        
        try:
            self.telemetry_queue.put_nowait(json.dumps(stream_data))
        except Exception:
            # Queue full, discard oldest
            try:
                self.telemetry_queue.get_nowait()
                self.telemetry_queue.put_nowait(json.dumps(stream_data))
            except Exception:
                pass
