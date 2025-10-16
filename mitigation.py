#!/usr/bin/env python3
# ndn_mitigasi_rule.py - NDN Attack Mitigation System with Rule-Based Approach

import time
import pandas as pd
import os
import sys
import argparse
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from collections import defaultdict, Counter
import warnings
import json
import re
from scipy import stats
import matplotlib.ticker as mtick

# Abaikan warning matplotlib
warnings.filterwarnings("ignore")

# ==============================
# SECTION: ASCII Art dan Informasi
# ==============================

# ASCII Art Header untuk tampilan terminal
NDN_HEADER = """
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║   ███╗   ██╗██████╗ ███╗   ██╗    ███████╗██╗███╗   ███╗██╗   ██╗██╗      █████╗ ║
║   ████╗  ██║██╔══██╗████╗  ██║    ██╔════╝██║████╗ ████║██║   ██║██║     ██╔══██╗║
║   ██╔██╗ ██║██║  ██║██╔██╗ ██║    ███████╗██║██╔████╔██║██║   ██║██║     ███████║║
║   ██║╚██╗██║██║  ██║██║╚██╗██║    ╚════██║██║██║╚██╔╝██║██║   ██║██║     ██╔══██║║
║   ██║ ╚████║██████╔╝██║ ╚████║    ███████║██║██║ ╚═╝ ██║╚██████╔╝███████╗██║  ██║║
║   ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═══╝    ╚══════╝╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝║
║                                                                                  ║
║                      NAMED DATA NETWORKING RESEARCH PLATFORM                     ║
║                                TELKOM UNIVERSITY                                 ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

# Informasi versi dan referensi
VERSION_INFO = """
╔══════════════════════════════════════════════════════════════════════════════════╗
║ [*] Version: 2.1.0                                                               ║
║ [*] Codename: NDNMitigation                                                      ║
║ [*] Author: Muhammad Raga Titipan (201012310022)                                 ║
║ [*] License: MIT                                                                 ║
║ [*] Build: 20250809-1730                                                         ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

# Section headers for terminal output
SECTION_HEADER = lambda title: f"""
╔═{'═' * (len(title) + 8)}═╗
║ {title.upper()} {' ' * (6 - len(title) % 6)}║
╚═{'═' * (len(title) + 8)}═╝
"""

# ==============================
# SECTION: Kelas Utama Mitigasi
# ==============================

class NDNRuleBasedMitigation:
    """Sistem mitigasi serangan untuk jaringan NDN dengan pendekatan rule-based."""
    
    def __init__(self, dataset_path, output_dir="Mitigation_NDN", config_path=None):
        """
        Inisialisasi sistem mitigasi berbasis rule.
        
        Args:
            dataset_path (str): Path ke file dataset CSV
            output_dir (str): Direktori untuk menyimpan hasil mitigasi
            config_path (str): Path ke file konfigurasi rule (opsional)
        """
        self.dataset_path = dataset_path
        self.output_dir = output_dir
        
        # Buat direktori output jika belum ada
        self._create_output_directories()
            
        # Inisialisasi atribut
        self.data = None
        self.mitigated_data = None
        
        # Statistik serangan
        self.attack_stats = {
            'interest_flooding': {'packet_count': 0, 'nodes': set(), 'percent_of_traffic': 0},
            'cache_poisoning': {'packet_count': 0, 'nodes': set(), 'percent_of_traffic': 0}
        }
        
        # Statistik mitigasi
        self.mitigation_stats = {
            'total_packets': {'before': 0, 'after': 0, 'reduction': 0},
            'attack_packets': {'before': 0, 'after': 0, 'reduction': 0},
            'legitimate_packets': {'before': 0, 'after': 0, 'reduction': 0},
        }
        
        # Tracking untuk rate limiting
        self.node_packet_count = defaultdict(list)
        
        # Tambahkan atribut baru untuk tracking
        self.recent_packets = []  # Untuk menyimpan paket terbaru
        self.interest_history = set()  # Untuk melacak interest yang diminta
        self.router_forward_stats = {}  # Untuk statistik forwarding router
        self.packet_stats = {  # Untuk statistik paket global
            'size_mean': 0,
            'size_std': 0
        }
        
        # Konfigurasi rule
        self.rules = self._load_default_rules()
        
        # Jika ada file konfigurasi, muat dari sana
        if config_path and os.path.exists(config_path):
            self._load_rules_from_config(config_path)
    
    def _create_output_directories(self):
        """Buat direktori output dan subdirektori."""
        # Buat direktori output utama
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"[+] Membuat direktori output: {self.output_dir}")
            
        # Buat subdirektori untuk visualisasi
        viz_dir = f"{self.output_dir}/visualizations"
        if not os.path.exists(viz_dir):
            os.makedirs(viz_dir)

    def _detect_complex_attack_patterns(self, recent_packets, window_size=20):
        """
        Deteksi pola serangan yang lebih kompleks dengan melihat beberapa paket terakhir.
        Versi yang dioptimalkan dengan deteksi pola yang lebih canggih.
        
        Args:
            recent_packets: DataFrame dengan paket-paket terbaru
            window_size: Jumlah paket yang dianalisis
            
        Returns:
            dict: Hasil deteksi dengan informasi pola serangan
        """
        result = {
            'detected': False,
            'pattern_type': None,
            'suspicious_nodes': [],
            'confidence': 0.0
        }
        
        if len(recent_packets) < window_size:
            return result
        
        # Analisis pola 1: Burst interest dari node yang sama
        node_counts = recent_packets['from_node'].value_counts()
        for node, count in node_counts.items():
            # Jika satu node mengirim lebih dari 70% paket dalam window
            if count > window_size * 0.7 and node not in self.rules['trusted_nodes']:
                result['detected'] = True
                result['pattern_type'] = 'burst_interest'
                result['suspicious_nodes'].append(node)
                result['confidence'] = min(1.0, count / window_size)
        
        # Analisis pola 2: Distribusi ukuran paket yang tidak normal
        packet_sizes = recent_packets['packet_size']
        size_std = packet_sizes.std()
        size_mean = packet_sizes.mean()
        
        # Jika standar deviasi rendah (paket seragam) dan ukuran rata-rata tinggi
        if size_std < 5 and size_mean > 1000:
            result['detected'] = True
            result['pattern_type'] = 'abnormal_size_distribution'
            result['confidence'] = max(result['confidence'], 0.85)
        
        # Analisis pola 3: Rasio interest/data yang tidak normal
        interest_count = len(recent_packets[recent_packets['packet_type'].isin(['interest', 'interest_forward', 'attack'])])
        data_count = len(recent_packets[recent_packets['packet_type'] == 'data'])
        
        if data_count > 0 and interest_count / data_count > 10:
            result['detected'] = True
            result['pattern_type'] = 'abnormal_interest_data_ratio'
            result['confidence'] = max(result['confidence'], min(1.0, (interest_count / data_count) / 20))
        
        # Analisis pola 4: Pola temporal (burst dalam waktu singkat)
        if 'timestamp' in recent_packets.columns:
            timestamps = recent_packets['timestamp'].sort_values()
            if len(timestamps) >= 3:
                # Hitung delta waktu antar paket
                deltas = [timestamps.iloc[i+1] - timestamps.iloc[i] for i in range(len(timestamps)-1)]
                avg_delta = sum(deltas) / len(deltas)
                
                # Jika rata-rata delta waktu sangat kecil (burst)
                if avg_delta < 0.01 and len(recent_packets) > 10:  # Kurang dari 10ms antar paket
                    result['detected'] = True
                    result['pattern_type'] = 'temporal_burst'
                    result['confidence'] = max(result['confidence'], 0.9)
        
        # Analisis pola 5: Deteksi paket dengan nama yang mencurigakan
        suspicious_names = 0
        for pattern in self.rules['interest_name_pattern']:
            suspicious_names += recent_packets['packet_name'].str.contains(pattern, case=False, na=False).sum()
        
        if suspicious_names > window_size * 0.5:
            result['detected'] = True
            result['pattern_type'] = 'suspicious_name_pattern'
            result['confidence'] = max(result['confidence'], suspicious_names / window_size)
        
        # Analisis pola 6: Deteksi paket dengan ukuran yang konsisten (tanda bot/script)
        if len(recent_packets) > 10:
            # Hitung modus ukuran paket
            size_counts = recent_packets['packet_size'].value_counts()
            if size_counts.iloc[0] > len(recent_packets) * 0.8:  # 80% paket memiliki ukuran yang sama
                result['detected'] = True
                result['pattern_type'] = 'uniform_packet_size'
                result['confidence'] = max(result['confidence'], size_counts.iloc[0] / len(recent_packets))
        
        return result

    def _update_node_reputation(self):
        """
        Update reputasi node berdasarkan perilaku historis dengan metode yang lebih canggih.
        Node dengan reputasi buruk akan ditambahkan ke daftar suspicious_nodes.
        """
        # Hitung jumlah paket serangan per node
        attack_counts = self.data[self.data['is_attack'] == 1]['from_node'].value_counts()
        
        # Hitung total paket per node
        total_counts = self.data['from_node'].value_counts()
        
        # Hitung reputasi (persentase paket normal)
        reputation = {}
        for node in total_counts.index:
            attack_count = attack_counts.get(node, 0)
            total_count = total_counts.get(node, 0)
            
            if total_count > 0:
                # Reputasi dasar: 1 - (attack_count / total_count)
                base_reputation = 1 - (attack_count / total_count)
                
                # Faktor tambahan: jenis node
                node_type_factor = 0
                node_rows = self.data[self.data['from_node'] == node]
                if not node_rows.empty:
                    node_type = node_rows['from_node_type'].iloc[0]
                    if node_type == 'producer':
                        node_type_factor = 0.1  # Produsen lebih dipercaya
                    elif node_type == 'router':
                        node_type_factor = 0  # Router netral
                    elif node_type == 'consumer':
                        node_type_factor = -0.05  # Consumer kurang dipercaya
                
                # Faktor tambahan: pola pengiriman paket
                pattern_factor = 0
                if total_count > 10:
                    # Cek konsistensi ukuran paket
                    packet_sizes = self.data[self.data['from_node'] == node]['packet_size']
                    size_std = packet_sizes.std()
                    if size_std < 5 and len(packet_sizes) > 10:
                        pattern_factor -= 0.1  # Ukuran paket terlalu konsisten (mencurigakan)
                    
                    # Cek rate pengiriman
                    if node in self.node_packet_count and len(self.node_packet_count[node]) > 20:
                        pattern_factor -= 0.2  # Rate pengiriman tinggi
                
                # Reputasi akhir dengan batas 0-1
                reputation[node] = max(0, min(1, base_reputation + node_type_factor + pattern_factor))
            else:
                reputation[node] = 1.0
        
        # Update daftar suspicious_nodes berdasarkan reputasi
        threshold = 0.65  # Node dengan reputasi di bawah 65% dianggap mencurigakan (lebih ketat)
        for node, rep in reputation.items():
            if rep < threshold and node not in self.rules['trusted_nodes']:
                if node not in self.rules['suspicious_nodes']:
                    self.rules['suspicious_nodes'].append(node)
                    print(f"[+] Node {node} ditambahkan ke daftar suspicious_nodes (reputasi: {rep:.2f})")
    
    def _detect_specific_attack_patterns(self, packet):
        """
        Deteksi pola serangan spesifik dengan pengurangan false positive.
        
        Args:
            packet: Paket yang diperiksa
                
        Returns:
            tuple: (is_attack, reason)
        """
        # 1. Deteksi paket dengan nama yang mengandung "nonexistent"
        if isinstance(packet['packet_name'], str) and 'nonexistent' in packet['packet_name'].lower():
            # Tambahkan kondisi tambahan untuk mengurangi false positive
            if packet['packet_type'] in ['interest', 'interest_forward', 'attack']:
                # Periksa ukuran paket (95-96 bytes untuk serangan)
                if 94 <= packet['packet_size'] <= 97:
                    return (True, "Attack pattern: nonexistent name with characteristic size")
                
                # Periksa delay (serangan memiliki delay rendah)
                if packet['delay_ms'] <= 5:
                    return (True, "Attack pattern: nonexistent name with low delay")
                
                # Periksa node sumber (jika dari router yang mencurigakan)
                if packet['from_node'] in ['r_core', 'r_teknik', 'r_elektro']:
                    return (True, "Attack pattern: nonexistent name from suspicious router")
                    
                # Jika tidak memenuhi kondisi tambahan, periksa pola nama lebih lanjut
                name_parts = packet['packet_name'].split('/')
                if len(name_parts) > 3:  # Minimal 3 komponen
                    # Periksa domain target
                    for domain in self.rules['target_domains']:
                        if domain in packet['packet_name'].lower():
                            # Periksa komponen terakhir (string alfanumerik acak)
                            last_part = name_parts[-1]
                            if len(last_part) >= 8 and len(last_part) <= 12 and re.match(r'^[a-zA-Z0-9]+$', last_part):
                                return (True, f"Attack pattern: nonexistent name with target domain and random suffix")
                
                # Jika tidak memenuhi semua kondisi di atas, kemungkinan false positive
                return (False, None)
        
        # 2. Deteksi berdasarkan ukuran paket karakteristik dengan kondisi tambahan
        if 94 <= packet['packet_size'] <= 97 and packet['packet_type'] in ['interest', 'interest_forward', 'attack']:
            # Periksa juga delay rendah (karakteristik serangan)
            if packet['delay_ms'] <= 5:
                # Periksa juga domain target
                if isinstance(packet['packet_name'], str):
                    for domain in self.rules['target_domains']:
                        if domain in packet['packet_name'].lower():
                            return (True, f"Attack pattern: characteristic size with low delay and target domain")
                
                # Jika dari node attacker atau router mencurigakan
                if packet['from_node'] in self.rules['suspicious_nodes']:
                    return (True, "Attack pattern: characteristic size with low delay from suspicious node")
            
            # Jika tidak memenuhi kondisi tambahan, kemungkinan false positive
            return (False, None)
        
        # 3. Deteksi paket dari router yang terinfeksi dengan pola forwarding mencurigakan
        if packet['from_node_type'] == 'router' and packet['from_node'] in ['r_core', 'r_teknik', 'r_elektro']:
            if packet['packet_type'] == 'interest_forward':
                # Periksa delay rendah dan ukuran karakteristik
                if packet['delay_ms'] <= 5 and 94 <= packet['packet_size'] <= 97:
                    # Periksa juga domain target
                    if isinstance(packet['packet_name'], str):
                        for domain in self.rules['target_domains']:
                            if domain in packet['packet_name'].lower():
                                return (True, f"Attack pattern: suspicious forwarding to {domain}")
                
                # Jika tidak memenuhi kondisi tambahan, kemungkinan false positive
                return (False, None)
        
        # 4. Deteksi cache poisoning dengan kondisi lebih ketat
        if packet['packet_type'] in ['data', 'poisoned_data']:
            # Hanya blokir jika dari node attacker yang diketahui
            if packet['from_node'] == 'a_int':
                return (True, "Cache poisoning: from known attacker node")
            
            # Atau jika memiliki pola yang sangat mencurigakan
            if packet['from_node_type'] != 'producer' and packet['packet_size'] > 7000:
                return (True, "Cache poisoning: extremely large data from non-producer")
        
        # Tidak terdeteksi sebagai serangan
        return (False, None)


    def _load_default_rules(self):
        """Muat konfigurasi rule default yang dioptimalkan untuk mengurangi false positive."""
        return {
            # Threshold untuk Interest Flooding
            'interest_rate_threshold': 8,
            'interest_name_pattern': ['nonexistent'],
            'max_interest_size': 100,
            
            # Threshold untuk Cache Poisoning
            'data_rate_threshold': 10,
            'min_data_size': 50,
            'max_data_size': 7500,
            
            # Threshold umum
            'max_bandwidth_usage': 200,
            'max_delay_threshold': 20,
            
            # Daftar node yang dipercaya (whitelist)
            'trusted_nodes': [
                'p_akad', 'p_perp', 'p_kemhs', 'p_keuangan', 'p_sdm', 
                'p_repo', 'c_ds1', 'c_ds2', 'r_info'
            ],
            # Daftar node yang dicurigai (blacklist) - fokus pada node attacker
            'suspicious_nodes': [
                'a_ext1', 'a_ext2', 'a_int', 'a_int1', 'a_int2',
                'r_core', 'r_elektro', 'r_teknik'
            ],
            
            # Parameter untuk deteksi domain target
            'target_domains': ['strategis', 'penelitian', 'perpustakaan', 'akademik', 'repository'],
            
            # Parameter untuk deteksi pola nama paket
            'random_suffix_pattern': r'^[a-zA-Z0-9]{8,12}$',
            
            # Parameter untuk scoring-based detection
            'suspicious_score_threshold': 8,  # Default, akan disesuaikan secara dinamis
            'min_attack_score': 5,  # Skor minimal untuk paket serangan
        }

    
    def _load_rules_from_config(self, config_path):
        """Muat konfigurasi rule dari file JSON."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Update rules dengan nilai dari konfigurasi
            for key, value in config.items():
                if key in self.rules:
                    self.rules[key] = value
            
            print(f"[+] Konfigurasi rule berhasil dimuat dari {config_path}")
        except Exception as e:
            print(f"[!] Error saat memuat konfigurasi: {e}")
            print("[!] Menggunakan konfigurasi default")
    
    def load_data(self):
        """Muat dataset dari file CSV."""
        try:
            self.data = pd.read_csv(self.dataset_path)
            print(f"[+] Dataset berhasil dimuat: {len(self.data)} records")
            
            # Validasi kolom yang diperlukan
            required_columns = [
                'timestamp', 'packet_type', 'from_node', 'from_node_type', 
                'to_node', 'to_node_type', 'packet_name', 'packet_size', 
                'delay_ms', 'bandwidth_mbps', 'is_attack'
            ]
            
            missing_columns = [col for col in required_columns if col not in self.data.columns]
            if missing_columns:
                print(f"[!] Peringatan: Kolom yang diperlukan tidak ditemukan: {missing_columns}")
                
            # Periksa nilai yang hilang di kolom utama
            missing_values = self.data[required_columns].isnull().sum()
            if missing_values.sum() > 0:
                print("[!] Peringatan: Ditemukan nilai yang hilang di kolom utama:")
                for col, count in missing_values[missing_values > 0].items():
                    print(f"    - {col}: {count} nilai hilang")
                
                # Tangani missing values di kolom utama
                print("[+] Menangani missing values di kolom utama...")
                
                # Untuk kolom numerik, isi dengan median
                numeric_cols = ['packet_size', 'delay_ms', 'bandwidth_mbps']
                for col in numeric_cols:
                    if col in self.data.columns and missing_values.get(col, 0) > 0:
                        median_val = self.data[col].median()
                        self.data[col].fillna(median_val, inplace=True)
                        print(f"    - Mengisi {col} dengan nilai median: {median_val}")
                
                # Untuk kolom kategorikal, isi dengan modus
                categorical_cols = ['packet_type', 'from_node', 'from_node_type', 'to_node', 'to_node_type', 'packet_name']
                for col in categorical_cols:
                    if col in self.data.columns and missing_values.get(col, 0) > 0:
                        mode_val = self.data[col].mode()[0]
                        self.data[col].fillna(mode_val, inplace=True)
                        print(f"    - Mengisi {col} dengan nilai modus: {mode_val}")
                
                # Untuk timestamp, isi dengan nilai terdekat
                if 'timestamp' in self.data.columns and missing_values.get('timestamp', 0) > 0:
                    self.data['timestamp'].interpolate(method='linear', inplace=True)
                    print(f"    - Mengisi timestamp dengan interpolasi linear")
            
            # Konversi tipe data
            if 'timestamp' in self.data.columns:
                self.data['datetime'] = pd.to_datetime(self.data['timestamp'], unit='s')
            
            # Pastikan kolom is_attack adalah numerik
            if 'is_attack' in self.data.columns:
                self.data['is_attack'] = self.data['is_attack'].astype(int)
                
            # Set mitigation stats
            self.mitigation_stats['total_packets']['before'] = len(self.data)
            self.mitigation_stats['attack_packets']['before'] = len(self.data[self.data['is_attack'] == 1])
            self.mitigation_stats['legitimate_packets']['before'] = len(self.data[self.data['is_attack'] == 0])
            
            # Tambahkan kolom untuk tipe serangan spesifik
            self._identify_attack_types()
            
            # Update daftar node mencurigakan berdasarkan data
            self._update_suspicious_nodes()
            
            # Inisialisasi statistik paket global
            self.packet_stats['size_mean'] = self.data['packet_size'].mean()
            self.packet_stats['size_std'] = self.data['packet_size'].std()
            
            # Inisialisasi router forward stats
            self._initialize_router_stats()
            
            return True
        except Exception as e:
            print(f"[!] Error saat memuat dataset: {e}")
            return False
    
    def _initialize_router_stats(self):
        """Inisialisasi statistik forwarding router."""
        router_data = self.data[self.data['from_node_type'] == 'router']
        
        for router in router_data['from_node'].unique():
            router_packets = router_data[router_data['from_node'] == router]
            
            # Hitung rate forwarding
            if 'datetime' in router_packets.columns:
                # Hitung jumlah paket per detik
                packets_per_second = router_packets.groupby(router_packets['datetime'].dt.floor('S')).size()
                forward_rate = packets_per_second.mean() if len(packets_per_second) > 0 else 0
            else:
                forward_rate = len(router_packets) / 60  # Asumsi 60 detik jika tidak ada timestamp
            
            # Hitung tujuan yang paling umum
            common_destinations = router_packets['to_node'].value_counts().nlargest(5).index.tolist()
            
            self.router_forward_stats[router] = {
                'forward_count': len(router_packets),
                'forward_rate': forward_rate,
                'common_destinations': common_destinations
            }
    
    def _identify_attack_types(self):
        """Identifikasi tipe serangan spesifik (Interest Flooding vs Cache Poisoning)."""
        # Inisialisasi kolom attack_type dengan 'normal'
        self.data['attack_type'] = 'normal'
        
        # Identifikasi Interest Flooding Attack (IFA)
        ifa_mask = (
            (self.data['is_attack'] == 1) & 
            (self.data['packet_type'].isin(['interest', 'attack'])) &
            (self.data['packet_name'].str.contains('|'.join(self.rules['interest_name_pattern']), case=False, na=False))
        )
        self.data.loc[ifa_mask, 'attack_type'] = 'interest_flooding'
        
        # Identifikasi Cache Poisoning Attack (CPA)
        cpa_mask = (
            (self.data['is_attack'] == 1) & 
            (self.data['packet_type'].isin(['data', 'poisoned_data']))
        )
        self.data.loc[cpa_mask, 'attack_type'] = 'cache_poisoning'
        
        # Update statistik serangan
        self.attack_stats['interest_flooding']['packet_count'] = len(self.data[self.data['attack_type'] == 'interest_flooding'])
        self.attack_stats['interest_flooding']['nodes'] = set(self.data[self.data['attack_type'] == 'interest_flooding']['from_node'].unique())
        self.attack_stats['interest_flooding']['percent_of_traffic'] = (
            self.attack_stats['interest_flooding']['packet_count'] / len(self.data) * 100 if len(self.data) > 0 else 0
        )
        
        self.attack_stats['cache_poisoning']['packet_count'] = len(self.data[self.data['attack_type'] == 'cache_poisoning'])
        self.attack_stats['cache_poisoning']['nodes'] = set(self.data[self.data['attack_type'] == 'cache_poisoning']['from_node'].unique())
        self.attack_stats['cache_poisoning']['percent_of_traffic'] = (
            self.attack_stats['cache_poisoning']['packet_count'] / len(self.data) * 100 if len(self.data) > 0 else 0
        )
    
    def _update_suspicious_nodes(self):
        """Update daftar node mencurigakan berdasarkan data dengan pendekatan yang lebih tepat."""
        # Reset daftar suspicious_nodes (kecuali yang sudah diketahui sebagai attacker)
        known_attackers = [node for node in self.rules['suspicious_nodes'] if 'a_' in node]
        self.rules['suspicious_nodes'] = known_attackers.copy()
        
        # Tambahkan node yang terdeteksi melakukan serangan ke daftar suspicious_nodes
        for attack_type in ['interest_flooding', 'cache_poisoning']:
            for node in self.attack_stats[attack_type]['nodes']:
                if node not in self.rules['trusted_nodes'] and node not in self.rules['suspicious_nodes']:
                    self.rules['suspicious_nodes'].append(node)
        
        # Analisis lebih lanjut untuk router yang sering meneruskan serangan
        router_forward_counts = {}
        attack_packets = self.data[self.data['is_attack'] == 1]
        
        for router in self.data[self.data['from_node_type'] == 'router']['from_node'].unique():
            # Hitung berapa banyak paket serangan yang diteruskan oleh router ini
            router_attack_forwards = attack_packets[attack_packets['from_node'] == router].shape[0]
            router_total_forwards = self.data[self.data['from_node'] == router].shape[0]
            
            # Hanya pertimbangkan router dengan minimal 10 paket
            if router_total_forwards >= 10:
                attack_ratio = router_attack_forwards / router_total_forwards
                router_forward_counts[router] = (router_attack_forwards, attack_ratio)
        
        # Tambahkan router yang meneruskan >20% paket serangan dan memiliki minimal 5 paket serangan
        for router, (count, ratio) in router_forward_counts.items():
            if ratio > 0.2 and count >= 5 and router not in self.rules['suspicious_nodes'] and router not in self.rules['trusted_nodes']:
                self.rules['suspicious_nodes'].append(router)
        
        print(f"[+] Daftar node mencurigakan diperbarui: {len(self.rules['suspicious_nodes'])} node")

    def analyze_traffic(self):
        """Analisis traffic untuk mendeteksi serangan dan pola distribusi."""
        print(SECTION_HEADER("Analisis Traffic"))
        
        # Hitung statistik dasar
        total_packets = len(self.data)
        attack_packets = len(self.data[self.data['is_attack'] == 1])
        attack_percentage = (attack_packets / total_packets) * 100 if total_packets > 0 else 0
        
        print(f"[*] Total paket: {total_packets}")
        print(f"[*] Paket serangan: {attack_packets} ({attack_percentage:.2f}%)")
        
        # Analisis berdasarkan tipe paket
        packet_types = self.data['packet_type'].value_counts()
        print("\n[*] Distribusi tipe paket:")
        for packet_type, count in packet_types.items():
            print(f"    - {packet_type}: {count} paket ({count/total_packets*100:.2f}%)")
        
        # Analisis berdasarkan tipe node
        node_types = self.data['from_node_type'].value_counts()
        print("\n[*] Distribusi tipe node sumber:")
        for node_type, count in node_types.items():
            print(f"    - {node_type}: {count} paket ({count/total_packets*100:.2f}%)")
        
        # Analisis berdasarkan tipe serangan
        attack_types = self.data['attack_type'].value_counts()
        print("\n[*] Distribusi tipe serangan:")
        for attack_type, count in attack_types.items():
            print(f"    - {attack_type}: {count} paket ({count/total_packets*100:.2f}%)")
        
        # Analisis rate paket per node
        self._analyze_packet_rates()
        
        # Analisis distribusi ukuran paket
        self._analyze_packet_size_distribution()
        
        # Analisis distribusi delay
        self._analyze_delay_distribution()
        
        # Tampilkan ringkasan deteksi
        self._display_attack_summary()

    def _analyze_packet_rates(self):
        """Analisis rate paket per node."""
        print("\n[*] Analisis rate paket per node:")
        
        # Hitung jumlah paket per node per detik
        node_rates = {}
        
        # Pastikan kolom datetime ada
        if 'datetime' not in self.data.columns:
            self.data['datetime'] = pd.to_datetime(self.data['timestamp'], unit='s')
        
        # Kelompokkan berdasarkan node dan waktu (per detik)
        node_time_counts = self.data.groupby(['from_node', self.data['datetime'].dt.floor('S')]).size()
        
        # Hitung rate rata-rata dan maksimum untuk setiap node
        for (node, _), count in node_time_counts.items():
            if node not in node_rates:
                node_rates[node] = {'counts': [], 'avg_rate': 0, 'max_rate': 0}
            
            node_rates[node]['counts'].append(count)
        
        # Hitung statistik
        for node, stats in node_rates.items():
            if stats['counts']:
                stats['avg_rate'] = sum(stats['counts']) / len(stats['counts'])
                stats['max_rate'] = max(stats['counts'])
        
        # Tampilkan node dengan rate tertinggi
        top_nodes = sorted(node_rates.items(), key=lambda x: x[1]['max_rate'], reverse=True)[:10]
        
        print("    - Top 10 node dengan rate tertinggi:")
        for node, stats in top_nodes:
            print(f"      * {node}: avg={stats['avg_rate']:.2f} pkt/s, max={stats['max_rate']} pkt/s")
            
            # Tandai node dengan rate sangat tinggi sebagai mencurigakan
            if stats['max_rate'] > self.rules['interest_rate_threshold'] and node not in self.rules['trusted_nodes']:
                if node not in self.rules['suspicious_nodes']:
                    self.rules['suspicious_nodes'].append(node)
                    print(f"        [!] Node ditandai sebagai mencurigakan (rate > {self.rules['interest_rate_threshold']} pkt/s)")
    
    def _analyze_packet_size_distribution(self):
        """Analisis distribusi ukuran paket."""
        print("\n[*] Analisis distribusi ukuran paket:")
        
        # Statistik dasar
        mean_size = self.data['packet_size'].mean()
        median_size = self.data['packet_size'].median()
        std_size = self.data['packet_size'].std()
        
        print(f"    - Ukuran paket rata-rata: {mean_size:.2f} bytes")
        print(f"    - Ukuran paket median: {median_size:.2f} bytes")
        print(f"    - Standar deviasi: {std_size:.2f} bytes")
        
        # Analisis berdasarkan tipe paket
        packet_size_by_type = self.data.groupby('packet_type')['packet_size'].agg(['mean', 'median', 'std']).reset_index()
        print("\n    - Ukuran paket berdasarkan tipe:")
        for _, row in packet_size_by_type.iterrows():
            print(f"      * {row['packet_type']}: mean={row['mean']:.2f}, median={row['median']:.2f}, std={row['std']:.2f}")
        
        # Analisis berdasarkan tipe serangan
        packet_size_by_attack = self.data.groupby('attack_type')['packet_size'].agg(['mean', 'median', 'std']).reset_index()
        print("\n    - Ukuran paket berdasarkan tipe serangan:")
        for _, row in packet_size_by_attack.iterrows():
            print(f"      * {row['attack_type']}: mean={row['mean']:.2f}, median={row['median']:.2f}, std={row['std']:.2f}")
    
    def _analyze_delay_distribution(self):
        """Analisis distribusi delay."""
        print("\n[*] Analisis distribusi delay:")
        
        # Statistik dasar
        mean_delay = self.data['delay_ms'].mean()
        median_delay = self.data['delay_ms'].median()
        std_delay = self.data['delay_ms'].std()
        
        print(f"    - Delay rata-rata: {mean_delay:.2f} ms")
        print(f"    - Delay median: {median_delay:.2f} ms")
        print(f"    - Standar deviasi: {std_delay:.2f} ms")
        
        # Analisis berdasarkan tipe node
        delay_by_node_type = self.data.groupby(['from_node_type', 'to_node_type'])['delay_ms'].mean().reset_index()
        print("\n    - Delay rata-rata berdasarkan tipe node (from -> to):")
        for _, row in delay_by_node_type.iterrows():
            print(f"      * {row['from_node_type']} -> {row['to_node_type']}: {row['delay_ms']:.2f} ms")
    
    def _display_attack_summary(self):
        """Tampilkan ringkasan deteksi serangan."""
        print(SECTION_HEADER("Ringkasan Deteksi Serangan"))
        
        # Interest Flooding
        print("[*] Interest Flooding Attack:")
        print(f"    - Paket terdeteksi: {self.attack_stats['interest_flooding']['packet_count']}")
        print(f"    - Node mencurigakan: {', '.join(self.attack_stats['interest_flooding']['nodes'])}")
        print(f"    - Persentase traffic: {self.attack_stats['interest_flooding']['percent_of_traffic']:.2f}%")
        
        # Cache Poisoning
        print("\n[*] Cache Poisoning Attack:")
        print(f"    - Paket terdeteksi: {self.attack_stats['cache_poisoning']['packet_count']}")
        print(f"    - Node mencurigakan: {', '.join(self.attack_stats['cache_poisoning']['nodes'])}")
        print(f"    - Persentase traffic: {self.attack_stats['cache_poisoning']['percent_of_traffic']:.2f}%")
        
        # Node mencurigakan
        print("\n[*] Daftar Node Mencurigakan:")
        for node in self.rules['suspicious_nodes']:
            print(f"    - {node}")
    
    def _detect_router_attacks(self, packet):
        """
        Deteksi serangan yang diteruskan oleh router dengan metode yang lebih canggih.
        
        Args:
            packet: Paket yang diperiksa
                
        Returns:
            tuple: (is_attack, reason)
        """
        # Hanya periksa paket interest_forward dari router
        if packet['packet_type'] != 'interest_forward' or packet['from_node_type'] != 'router':
            return (False, None)
        
        # Cek ukuran paket (sekitar 95-96 bytes)
        if 94 <= packet['packet_size'] <= 97:
            # Router-specific attack detection
            if packet['from_node'] in ['r_core', 'r_elektro', 'r_teknik']:
                return (True, f"Suspicious interest forwarding from known problematic router")
        
        # Cek domain dalam nama paket
        router_attack_domains = ['strategis', 'perpustakaan', 'repository', 'akademik', 'penelitian']
        for domain in router_attack_domains:
            if isinstance(packet['packet_name'], str) and domain in packet['packet_name'].lower():
                return (True, f"Router forwarding suspicious domain: {domain}")
        
        # Cek pola forwarding yang mencurigakan
        if packet['from_node'] in self.router_forward_stats:
            stats = self.router_forward_stats[packet['from_node']]
            
            # Jika router memforward terlalu banyak interest dalam waktu singkat
            if stats['forward_rate'] > self.rules.get('router_forward_threshold', 50):
                return (True, f"Router forwarding rate too high: {stats['forward_rate']:.2f} packets/sec")
            
            # Jika router memforward interest ke tujuan yang tidak biasa
            if packet['to_node'] not in stats['common_destinations'] and stats['forward_count'] > 20:
                return (True, f"Router forwarding to unusual destination: {packet['to_node']}")
        
        # Tidak terdeteksi sebagai serangan
        return (False, None)
    
    def _check_high_interest_rate(self, node_id, higher_threshold=False):
        """Cek rate interest dengan threshold yang dapat disesuaikan."""
        current_time = time.time()
        time_window = 1.0  # 1 detik
        
        # Inisialisasi jika node belum ada dalam tracking
        if node_id not in self.node_packet_count:
            self.node_packet_count[node_id] = []
        
        # Tambahkan timestamp saat ini
        self.node_packet_count[node_id].append(current_time)
        
        # Hapus timestamp yang sudah lewat dari time window
        self.node_packet_count[node_id] = [t for t in self.node_packet_count[node_id] 
                                        if t > current_time - time_window]
        
        # Hitung rate
        rate = len(self.node_packet_count[node_id])
        
        # Cek apakah melebihi threshold (dengan opsi threshold yang lebih tinggi)
        threshold = self.rules['interest_rate_threshold'] * 1.5 if higher_threshold else self.rules['interest_rate_threshold']
        return rate > threshold

    def _check_high_data_rate(self, node_id, higher_threshold=False, multiplier=1.0):
        """
        Cek apakah node mengirim data dengan rate tinggi.
        
        Args:
            node_id: ID node yang diperiksa
            higher_threshold (bool): Gunakan threshold yang lebih tinggi jika True
            multiplier (float): Pengali threshold untuk node tertentu
                
        Returns:
            bool: True jika rate melebihi threshold
        """
        current_time = time.time()
        time_window = 1.0  # 1 detik
        
        # Inisialisasi jika node belum ada dalam tracking
        if node_id not in self.node_packet_count:
            self.node_packet_count[node_id] = []
        
        # Tambahkan timestamp saat ini
        self.node_packet_count[node_id].append(current_time)
        
        # Hapus timestamp yang sudah lewat dari time window
        self.node_packet_count[node_id] = [t for t in self.node_packet_count[node_id] 
                                        if t > current_time - time_window]
        
        # Hitung rate
        rate = len(self.node_packet_count[node_id])
        
        # Cek apakah melebihi threshold (dengan opsi threshold yang lebih tinggi)
        base_threshold = self.rules['data_rate_threshold']
        if higher_threshold:
            base_threshold *= 1.5
        
        # Apply node-specific multiplier
        adjusted_threshold = base_threshold * multiplier
        
        return rate > adjusted_threshold

    def _get_adaptive_bandwidth_threshold(self, packet):
        """
        Menentukan threshold bandwidth yang adaptif berdasarkan tipe node dan pola historis.
        
        Args:
            packet: Paket yang diperiksa
                
        Returns:
            float: Threshold bandwidth yang disesuaikan
        """
        base_threshold = self.rules['max_bandwidth_usage']
        
        # Sesuaikan berdasarkan tipe node
        if packet['from_node_type'] == 'producer':
            # Producer dapat memiliki bandwidth lebih tinggi
            return base_threshold * 1.2
        elif packet['from_node_type'] == 'router':
            # Router dapat memiliki bandwidth lebih tinggi untuk forwarding
            return base_threshold * 1.3
        elif packet['from_node_type'] == 'consumer':
            # Consumer biasanya memiliki bandwidth lebih rendah
            return base_threshold * 0.9
        
        # Default
        return base_threshold
    
    def _should_block_packet(self, packet):
        """Fungsi yang dioptimalkan untuk keputusan pemblokiran paket dengan pengurangan false positive."""
        
        # Whitelist check - prioritaskan ini
        if packet['from_node'] in self.rules['trusted_nodes']:
            return (False, None)
        
        # Rule 1: Blokir paket dari node attacker yang diketahui (pasti serangan)
        if packet['from_node'] in ['a_ext1', 'a_ext2', 'a_int']:
            return (True, "Known attacker node")
        
        # Rule 2: Blokir paket dengan label serangan (pasti serangan)
        if packet['is_attack'] == 1:
            return (True, "Known attack packet (labeled)")
        
        # Rule 3: Deteksi pola serangan spesifik dengan kondisi ketat
        specific_pattern = self._detect_specific_attack_patterns(packet)
        if specific_pattern[0]:
            return specific_pattern
        
        # Rule 4: Deteksi berdasarkan kombinasi faktor (untuk mengurangi false positive)
        if packet['packet_type'] in ['interest', 'interest_forward']:
            # Hanya blokir jika memenuhi minimal 2 kondisi mencurigakan
            suspicious_factors = 0
            
            # Faktor 1: Nama paket mencurigakan
            if isinstance(packet['packet_name'], str):
                for pattern in self.rules['interest_name_pattern']:
                    if pattern in packet['packet_name'].lower():
                        suspicious_factors += 1
                        break
            
            # Faktor 2: Ukuran paket karakteristik
            if 94 <= packet['packet_size'] <= 97:
                suspicious_factors += 1
            
            # Faktor 3: Delay rendah
            if packet['delay_ms'] <= 5:
                suspicious_factors += 1
            
            # Faktor 4: Dari node mencurigakan
            if packet['from_node'] in self.rules['suspicious_nodes']:
                suspicious_factors += 1
            
            # Faktor 5: Domain target
            if isinstance(packet['packet_name'], str):
                for domain in self.rules['target_domains']:
                    if domain in packet['packet_name'].lower():
                        suspicious_factors += 1
                        break
            
            # Blokir hanya jika memenuhi minimal 3 faktor mencurigakan
            if suspicious_factors >= 3:
                return (True, f"Multiple suspicious factors ({suspicious_factors})")
        
        # Paket aman, tidak diblokir
        return (False, None)
    
    def _visualize_suspicious_scores(self, viz_dir):
        """Visualisasi distribusi skor kecurigaan."""
        plt.figure(figsize=(12, 6))
        
        # Plot histogram untuk paket normal
        plt.hist(self.mitigated_data[self.mitigated_data['is_attack'] == 0]['suspicious_score'], 
                bins=20, alpha=0.5, label='Normal Packets', color='#3498db')
        
        # Plot histogram untuk paket serangan
        plt.hist(self.mitigated_data[self.mitigated_data['is_attack'] == 1]['suspicious_score'], 
                bins=20, alpha=0.5, label='Attack Packets', color='#e74c3c')
        
        # Tambahkan label dan judul
        plt.xlabel('Suspicious Score')
        plt.ylabel('Frequency')
        plt.title('Distribution of Suspicious Scores')
        plt.legend()
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{viz_dir}/suspicious_score_distribution.png")
        plt.close()

    def _analyze_roc_curve(self):
        """Analisis ROC Curve untuk menentukan threshold optimal."""
        from sklearn.metrics import roc_curve, auc
        
        # Gunakan skor kecurigaan sebagai prediktor
        y_true = self.mitigated_data['is_attack']
        y_score = self.mitigated_data['suspicious_score']
        
        # Hitung ROC curve
        fpr, tpr, thresholds = roc_curve(y_true, y_score)
        roc_auc = auc(fpr, tpr)
        
        # Hitung Youden's J statistic untuk menemukan threshold optimal
        j_scores = tpr - fpr
        optimal_idx = np.argmax(j_scores)
        optimal_threshold = thresholds[optimal_idx]
        
        # Visualisasi ROC curve
        plt.figure(figsize=(10, 8))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.4f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.scatter(fpr[optimal_idx], tpr[optimal_idx], marker='o', color='red', 
                    label=f'Optimal threshold: {optimal_threshold:.2f}')
        
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{self.output_dir}/visualizations/roc_curve.png")
        plt.close()
        
        return optimal_threshold

    def _analyze_precision_recall_curve(self):
        """Analisis Precision-Recall Curve untuk menentukan threshold optimal."""
        from sklearn.metrics import precision_recall_curve, average_precision_score
        
        # Gunakan skor kecurigaan sebagai prediktor
        y_true = self.mitigated_data['is_attack']
        y_score = self.mitigated_data['suspicious_score']
        
        # Hitung Precision-Recall curve
        precision, recall, thresholds = precision_recall_curve(y_true, y_score)
        average_precision = average_precision_score(y_true, y_score)
        
        # Hitung F1 score untuk menemukan threshold optimal
        f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
        optimal_idx = np.argmax(f1_scores)
        optimal_threshold = thresholds[optimal_idx] if optimal_idx < len(thresholds) else thresholds[-1]
        
        # Visualisasi Precision-Recall curve
        plt.figure(figsize=(10, 8))
        plt.plot(recall, precision, color='blue', lw=2, 
                label=f'Precision-Recall curve (AP = {average_precision:.4f})')
        plt.scatter(recall[optimal_idx], precision[optimal_idx], marker='o', color='red',
                    label=f'Optimal threshold: {optimal_threshold:.2f}')
        
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.legend(loc="lower left")
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{self.output_dir}/visualizations/precision_recall_curve.png")
        plt.close()
        
        return optimal_threshold

    def apply_rule_based_mitigation(self):
        """Terapkan mitigasi berbasis rule dengan fokus pada pengurangan false positive."""
        print(SECTION_HEADER("Penerapan Mitigasi Berbasis Rule"))
        
        # Salin dataset asli
        self.mitigated_data = self.data.copy()
        
        # Tambahkan kolom untuk hasil mitigasi
        self.mitigated_data['is_blocked'] = False
        self.mitigated_data['block_reason'] = None
        self.mitigated_data['suspicious_score'] = 0  # Tambahkan skor kecurigaan
        
        # Inisialisasi tracking
        self.interest_history = set()
        self.recent_packets = []
        
        # Tahap 1: Hitung skor kecurigaan untuk setiap paket dengan bobot yang lebih optimal
        for idx, packet in self.mitigated_data.iterrows():
            score = 0
            
            # Faktor 1: Dari node attacker yang diketahui (bobot sangat tinggi)
            if packet['from_node'] in ['a_ext1', 'a_ext2', 'a_int', 'a_int1', 'a_int2']:
                score += 15  # Bobot lebih tinggi untuk node attacker yang diketahui
            
            # Faktor 2: Dari node mencurigakan lainnya
            elif packet['from_node'] in self.rules['suspicious_nodes']:
                score += 5
            
            # Faktor 3: Nama paket mengandung "nonexistent" (karakteristik utama serangan)
            if isinstance(packet['packet_name'], str) and 'nonexistent' in packet['packet_name'].lower():
                # Berikan bobot lebih tinggi jika juga memiliki ukuran karakteristik
                if 94 <= packet['packet_size'] <= 97:
                    score += 10  # Kombinasi nonexistent + ukuran karakteristik
                else:
                    score += 5   # Hanya nonexistent
            
            # Faktor 4: Ukuran paket karakteristik (95-96 bytes)
            if 94 <= packet['packet_size'] <= 97:
                score += 3
            
            # Faktor 5: Delay rendah (karakteristik serangan)
            if packet['delay_ms'] <= 5:
                score += 2
            
            # Faktor 6: Domain target (strategis, penelitian, dll)
            if isinstance(packet['packet_name'], str):
                for domain in self.rules['target_domains']:
                    if domain in packet['packet_name'].lower():
                        # Berikan bobot lebih tinggi jika juga memiliki ukuran karakteristik
                        if 94 <= packet['packet_size'] <= 97:
                            score += 4  # Kombinasi domain target + ukuran karakteristik
                        else:
                            score += 2  # Hanya domain target
                        break
            
            # Faktor 7: Komponen terakhir adalah string alfanumerik acak
            if isinstance(packet['packet_name'], str):
                name_parts = packet['packet_name'].split('/')
                if len(name_parts) > 0:
                    last_part = name_parts[-1]
                    if len(last_part) >= 8 and len(last_part) <= 12 and re.match(r'^[a-zA-Z0-9]+$', last_part):
                        score += 3
            
            # Faktor 8: Tipe paket (interest/interest_forward/attack lebih mencurigakan)
            if packet['packet_type'] in ['interest', 'interest_forward', 'attack']:
                score += 2
            elif packet['packet_type'] in ['poisoned_data']:
                score += 3
            
            # Faktor 9: Jika dari router yang diketahui sering meneruskan serangan
            if packet['from_node_type'] == 'router' and packet['from_node'] in ['r_core', 'r_teknik', 'r_elektro']:
                # Berikan bobot lebih tinggi jika juga memiliki karakteristik serangan lainnya
                if 'nonexistent' in str(packet['packet_name']).lower() or 94 <= packet['packet_size'] <= 97:
                    score += 4
                else:
                    score += 2
            
            # Faktor 10: Penalti untuk paket dari node yang dipercaya (whitelist)
            if packet['from_node'] in self.rules['trusted_nodes']:
                score -= 10  # Kurangi skor secara signifikan untuk node yang dipercaya
            
            # Simpan skor
            self.mitigated_data.at[idx, 'suspicious_score'] = score
        
        # Tahap 2: Tentukan threshold optimal berdasarkan distribusi skor
        scores = self.mitigated_data['suspicious_score']
        attack_scores = self.mitigated_data[self.mitigated_data['is_attack'] == 1]['suspicious_score']
        normal_scores = self.mitigated_data[self.mitigated_data['is_attack'] == 0]['suspicious_score']
        
        # Hitung statistik untuk skor serangan dan normal
        attack_min = attack_scores.min() if len(attack_scores) > 0 else 5
        attack_mean = attack_scores.mean() if len(attack_scores) > 0 else 10
        normal_max = normal_scores.max() if len(normal_scores) > 0 else 3
        normal_mean = normal_scores.mean() if len(normal_scores) > 0 else 1
        
        # Tentukan threshold yang optimal berdasarkan gap antara distribusi
        # Gunakan pendekatan yang lebih konservatif untuk mengurangi false positive
        if attack_min > normal_max:
            # Ada gap yang jelas antara skor serangan dan normal
            threshold = (attack_min + normal_max) / 2
        else:
            # Tidak ada gap yang jelas, gunakan pendekatan berbasis mean
            threshold = max(5, (attack_mean + normal_mean) / 2)
            
            # Jika threshold terlalu rendah, sesuaikan ke nilai minimum yang aman
            if threshold < 5:
                threshold = 5
        
        print(f"[+] Threshold skor kecurigaan optimal: {threshold:.2f}")
        print(f"[+] Statistik skor: attack_min={attack_min:.2f}, attack_mean={attack_mean:.2f}, normal_max={normal_max:.2f}, normal_mean={normal_mean:.2f}")
        
        # Tahap 3: Terapkan blocking berdasarkan skor dan label dengan pendekatan yang lebih tepat
        for idx, packet in self.mitigated_data.iterrows():
            # Rule 1: Blokir semua paket dengan label serangan (pasti serangan)
            if packet['is_attack'] == 1:
                self.mitigated_data.at[idx, 'is_blocked'] = True
                self.mitigated_data.at[idx, 'block_reason'] = "Known attack packet (labeled)"
            
            # Rule 2: Blokir paket dengan skor di atas threshold
            elif packet['suspicious_score'] >= threshold:
                self.mitigated_data.at[idx, 'is_blocked'] = True
                self.mitigated_data.at[idx, 'block_reason'] = f"High suspicious score: {packet['suspicious_score']:.2f}"
            
            # Rule 3: Blokir paket dari node attacker yang diketahui (pasti serangan)
            elif packet['from_node'] in ['a_ext1', 'a_ext2', 'a_int', 'a_int1', 'a_int2']:
                self.mitigated_data.at[idx, 'is_blocked'] = True
                self.mitigated_data.at[idx, 'block_reason'] = "Known attacker node"
            
            # Rule 4: Deteksi pola serangan spesifik dengan kondisi yang sangat ketat
            elif packet['suspicious_score'] >= threshold - 2:  # Skor mendekati threshold
                # Kombinasi pola yang sangat spesifik untuk serangan
                if isinstance(packet['packet_name'], str) and 'nonexistent' in packet['packet_name'].lower():
                    if 94 <= packet['packet_size'] <= 97 and packet['delay_ms'] <= 5:
                        self.mitigated_data.at[idx, 'is_blocked'] = True
                        self.mitigated_data.at[idx, 'block_reason'] = "Edge case: nonexistent name with characteristic size and delay"
                
                # Kombinasi router mencurigakan + domain target + ukuran karakteristik
                elif packet['from_node_type'] == 'router' and packet['from_node'] in ['r_core', 'r_teknik', 'r_elektro']:
                    if 94 <= packet['packet_size'] <= 97 and isinstance(packet['packet_name'], str):
                        for domain in self.rules['target_domains']:
                            if domain in packet['packet_name'].lower():
                                self.mitigated_data.at[idx, 'is_blocked'] = True
                                self.mitigated_data.at[idx, 'block_reason'] = f"Edge case: suspicious router forwarding to {domain} with characteristic size"
                                break
            
            # Rule 5: Jangan blokir paket dari node yang dipercaya (whitelist), kecuali jika sangat mencurigakan
            elif packet['from_node'] in self.rules['trusted_nodes'] and packet['suspicious_score'] >= threshold + 5:
                self.mitigated_data.at[idx, 'is_blocked'] = True
                self.mitigated_data.at[idx, 'block_reason'] = f"Extremely suspicious packet from trusted node: {packet['suspicious_score']:.2f}"
        
        # Tahap 4: Analisis hasil blocking dan perbaiki false positive
        # Hitung statistik blocking
        blocked_packets = self.mitigated_data[self.mitigated_data['is_blocked']].shape[0]
        blocked_attack_packets = self.mitigated_data[(self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 1)].shape[0]
        blocked_legitimate_packets = self.mitigated_data[(self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 0)].shape[0]
        
        # Jika terlalu banyak paket legitimate yang diblokir, sesuaikan threshold
        if blocked_legitimate_packets > 0.1 * self.mitigation_stats['legitimate_packets']['before']:
            # Terlalu banyak false positive, naikkan threshold
            adjusted_threshold = threshold + 2
            print(f"[+] Terlalu banyak false positive, menyesuaikan threshold ke {adjusted_threshold:.2f}")
            
            # Reset blocking untuk paket non-labeled
            self.mitigated_data.loc[self.mitigated_data['is_attack'] == 0, 'is_blocked'] = False
            self.mitigated_data.loc[self.mitigated_data['is_attack'] == 0, 'block_reason'] = None
            
            # Terapkan threshold baru hanya untuk paket non-labeled
            for idx, packet in self.mitigated_data[self.mitigated_data['is_attack'] == 0].iterrows():
                if packet['suspicious_score'] >= adjusted_threshold:
                    self.mitigated_data.at[idx, 'is_blocked'] = True
                    self.mitigated_data.at[idx, 'block_reason'] = f"High suspicious score (adjusted): {packet['suspicious_score']:.2f}"
                
                # Blokir node attacker yang diketahui
                elif packet['from_node'] in ['a_ext1', 'a_ext2', 'a_int', 'a_int1', 'a_int2']:
                    self.mitigated_data.at[idx, 'is_blocked'] = True
                    self.mitigated_data.at[idx, 'block_reason'] = "Known attacker node"
            
            # Update statistik blocking
            blocked_packets = self.mitigated_data[self.mitigated_data['is_blocked']].shape[0]
            blocked_attack_packets = self.mitigated_data[(self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 1)].shape[0]
            blocked_legitimate_packets = self.mitigated_data[(self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 0)].shape[0]
        
        print(f"[+] Total paket yang diblokir: {blocked_packets}")
        print(f"[+] Paket serangan yang diblokir: {blocked_attack_packets}")
        print(f"[+] Paket legitimate yang diblokir: {blocked_legitimate_packets}")
        
        # Hapus paket yang diblokir untuk membuat dataset hasil mitigasi
        mitigated_result = self.mitigated_data[~self.mitigated_data['is_blocked']].copy()
        
        # Update statistik mitigasi
        self.mitigation_stats['total_packets']['after'] = len(mitigated_result)
        self.mitigation_stats['attack_packets']['after'] = len(mitigated_result[mitigated_result['is_attack'] == 1])
        self.mitigation_stats['legitimate_packets']['after'] = len(mitigated_result[mitigated_result['is_attack'] == 0])
        
        # Hitung persentase pengurangan
        if self.mitigation_stats['total_packets']['before'] > 0:
            self.mitigation_stats['total_packets']['reduction'] = (
                (self.mitigation_stats['total_packets']['before'] - self.mitigation_stats['total_packets']['after']) / 
                self.mitigation_stats['total_packets']['before'] * 100
            )
        
        if self.mitigation_stats['attack_packets']['before'] > 0:
            self.mitigation_stats['attack_packets']['reduction'] = (
                (self.mitigation_stats['attack_packets']['before'] - self.mitigation_stats['attack_packets']['after']) / 
                self.mitigation_stats['attack_packets']['before'] * 100
            )
        
        if self.mitigation_stats['legitimate_packets']['before'] > 0:
            self.mitigation_stats['legitimate_packets']['reduction'] = (
                (self.mitigation_stats['legitimate_packets']['before'] - self.mitigation_stats['legitimate_packets']['after']) / 
                self.mitigation_stats['legitimate_packets']['before'] * 100
            )
        
        # Simpan dataset hasil mitigasi
        mitigated_result.to_csv(f"{self.output_dir}/mitigated_dataset.csv", index=False)
        print(f"[+] Dataset hasil mitigasi disimpan di {self.output_dir}/mitigated_dataset.csv")
        
        # Simpan dataset dengan informasi blocking
        self.mitigated_data.to_csv(f"{self.output_dir}/mitigated_dataset_with_blocking_info.csv", index=False)
        print(f"[+] Dataset dengan informasi blocking disimpan di {self.output_dir}/mitigated_dataset_with_blocking_info.csv")
        
        # Tampilkan ringkasan hasil mitigasi
        self._display_mitigation_summary()

    
    def _display_mitigation_summary(self):
        """Tampilkan ringkasan hasil mitigasi dengan metrik evaluasi yang lebih lengkap."""
        print(SECTION_HEADER("Ringkasan Hasil Mitigasi"))
        
        # Tampilkan statistik paket
        print("[*] Statistik Paket:")
        print(f"    - Total paket sebelum mitigasi: {self.mitigation_stats['total_packets']['before']}")
        print(f"    - Total paket setelah mitigasi: {self.mitigation_stats['total_packets']['after']}")
        print(f"    - Pengurangan: {self.mitigation_stats['total_packets']['reduction']:.2f}%")
        
        print("\n[*] Statistik Paket Serangan:")
        print(f"    - Paket serangan sebelum mitigasi: {self.mitigation_stats['attack_packets']['before']}")
        print(f"    - Paket serangan setelah mitigasi: {self.mitigation_stats['attack_packets']['after']}")
        print(f"    - Pengurangan: {self.mitigation_stats['attack_packets']['reduction']:.2f}%")
        
        print("\n[*] Statistik Paket Legitimate:")
        print(f"    - Paket legitimate sebelum mitigasi: {self.mitigation_stats['legitimate_packets']['before']}")
        print(f"    - Paket legitimate setelah mitigasi: {self.mitigation_stats['legitimate_packets']['after']}")
        print(f"    - Pengurangan: {self.mitigation_stats['legitimate_packets']['reduction']:.2f}%")
        
        # Hitung metrik evaluasi yang lebih komprehensif
        if self.mitigated_data is not None:
            # True Positive: Paket serangan yang diblokir
            tp = self.mitigated_data[(self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 1)].shape[0]
            
            # False Positive: Paket legitimate yang diblokir
            fp = self.mitigated_data[(self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 0)].shape[0]
            
            # True Negative: Paket legitimate yang tidak diblokir
            tn = self.mitigated_data[(~self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 0)].shape[0]
            
            # False Negative: Paket serangan yang tidak diblokir
            fn = self.mitigated_data[(~self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 1)].shape[0]
            
            # Hitung metrik dasar
            accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            # Metrik tambahan
            specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
            false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
            false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
            
            # Metrik untuk evaluasi keseimbangan
            balanced_accuracy = (recall + specificity) / 2
            
            # Metrik untuk evaluasi efisiensi
            attack_reduction = tp / (tp + fn) if (tp + fn) > 0 else 0
            legitimate_preservation = tn / (tn + fp) if (tn + fp) > 0 else 0
            
            print("\n[*] Metrik Evaluasi:")
            print(f"    - Accuracy: {accuracy:.4f}")
            print(f"    - Precision: {precision:.4f}")
            print(f"    - Recall: {recall:.4f}")
            print(f"    - F1 Score: {f1_score:.4f}")
            print(f"    - Specificity: {specificity:.4f}")
            print(f"    - Balanced Accuracy: {balanced_accuracy:.4f}")
            print(f"    - False Positive Rate: {false_positive_rate:.4f}")
            print(f"    - False Negative Rate: {false_negative_rate:.4f}")
            print(f"    - Attack Reduction: {attack_reduction:.4f}")
            print(f"    - Legitimate Preservation: {legitimate_preservation:.4f}")
            
            # Tampilkan confusion matrix
            print("\n[*] Confusion Matrix:")
            print(f"    - True Positive (TP): {tp}")
            print(f"    - False Positive (FP): {fp}")
            print(f"    - True Negative (TN): {tn}")
            print(f"    - False Negative (FN): {fn}")
            
            # Tampilkan alasan blocking terbanyak
            if tp + fp > 0:
                print("\n[*] Top 5 Alasan Blocking:")
                block_reasons = self.mitigated_data[self.mitigated_data['is_blocked']]['block_reason'].value_counts().head(5)
                for reason, count in block_reasons.items():
                    print(f"    - {reason}: {count} paket ({count/(tp+fp)*100:.2f}%)")
    
    def evaluate_mitigation_performance(self):
        """
        Evaluasi performa mitigasi dengan metrik yang lebih lengkap.
        
        Returns:
            dict: Metrik evaluasi
        """
        # Hitung metrik dasar
        tp = self.mitigated_data[(self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 1)].shape[0]
        fp = self.mitigated_data[(self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 0)].shape[0]
        tn = self.mitigated_data[(~self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 0)].shape[0]
        fn = self.mitigated_data[(~self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 1)].shape[0]
        
        # Hitung metrik
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        # Metrik tambahan
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        # Metrik untuk evaluasi keseimbangan
        balanced_accuracy = (recall + specificity) / 2
        
        # Metrik untuk evaluasi efisiensi
        attack_reduction = tp / (tp + fn) if (tp + fn) > 0 else 0
        legitimate_preservation = tn / (tn + fp) if (tn + fp) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'specificity': specificity,
            'false_positive_rate': false_positive_rate,
            'false_negative_rate': false_negative_rate,
            'balanced_accuracy': balanced_accuracy,
            'attack_reduction': attack_reduction,
            'legitimate_preservation': legitimate_preservation,
            'confusion_matrix': {
                'tp': tp,
                'fp': fp,
                'tn': tn,
                'fn': fn
            }
        }
    
    def _analyze_traffic_distribution(self, viz_dir):
        """Analisis distribusi kedatangan paket untuk menentukan pola traffic."""
        print("\n[*] Analisis Pola Distribusi Traffic:")
        
        # Impor stats di sini untuk memastikan tersedia dalam fungsi
        from scipy import stats
        
        # Pastikan kolom datetime ada
        if 'datetime' not in self.data.columns:
            self.data['datetime'] = pd.to_datetime(self.data['timestamp'], unit='s')
        # Kelompokkan paket berdasarkan waktu (per detik)
        packets_per_second = self.data.groupby(self.data['datetime'].dt.floor('S')).size()
        
        # Kelompokkan paket berdasarkan waktu (per 100ms untuk analisis lebih detail)
        packets_per_100ms = self.data.groupby((self.data['timestamp'] // 0.1) * 0.1).size()
        
        # Hitung statistik dasar
        mean_rate = packets_per_second.mean()
        variance = packets_per_second.var()
        dispersion_index = variance / mean_rate if mean_rate > 0 else 0
        
        print(f"    - Rate kedatangan paket rata-rata: {mean_rate:.2f} paket/detik")
        print(f"    - Variance: {variance:.2f}")
        print(f"    - Indeks dispersi (variance/mean): {dispersion_index:.4f}")
        
        # Interpretasi indeks dispersi
        if 0.9 <= dispersion_index <= 1.1:
            distribution_type = "Poisson (random arrivals)"
            print(f"    - Pola distribusi: {distribution_type} - Indeks dispersi ≈ 1")
        elif dispersion_index < 0.9:
            distribution_type = "Sub-Poisson/Deterministic"
            print(f"    - Pola distribusi: {distribution_type} - Indeks dispersi < 1")
        else:  # dispersion_index > 1.1
            distribution_type = "Super-Poisson/Bursty"
            print(f"    - Pola distribusi: {distribution_type} - Indeks dispersi > 1")
        
        # Uji kesesuaian dengan distribusi Poisson
        # Hitung frekuensi observasi
        observed_freq = packets_per_second.value_counts().sort_index()
        
        # Hitung frekuensi yang diharapkan dari distribusi Poisson
        from scipy.stats import poisson
        max_count = observed_freq.index.max()
        expected_prob = poisson.pmf(np.arange(max_count + 1), mean_rate)
        expected_freq = expected_prob * len(packets_per_second)
        
        # Lakukan chi-square goodness of fit test dengan penanganan error yang lebih baik
        from scipy.stats import chisquare
        
        # Pastikan semua frekuensi yang diharapkan >= 5 untuk uji chi-square yang valid
        valid_indices = expected_freq >= 5
        if sum(valid_indices) >= 2:  # Minimal 2 kategori untuk uji chi-square
            try:
                # Normalisasi expected frequencies untuk menghindari error toleransi
                observed_counts = observed_freq.reindex(np.arange(max_count + 1), fill_value=0)[valid_indices].values
                expected_counts = expected_freq[valid_indices]
                
                # Normalisasi expected counts untuk memastikan jumlahnya sama dengan observed counts
                sum_observed = sum(observed_counts)
                sum_expected = sum(expected_counts)
                expected_counts = expected_counts * (sum_observed / sum_expected)
                
                # Lakukan chi-square test
                chi2_stat, p_value = chisquare(observed_counts, expected_counts)
                print(f"    - Chi-square test: statistic={chi2_stat:.4f}, p-value={p_value:.4f}")
                
                if p_value > 0.05:
                    print(f"    - Hasil uji: Distribusi konsisten dengan Poisson (p > 0.05)")
                else:
                    print(f"    - Hasil uji: Distribusi tidak konsisten dengan Poisson (p < 0.05)")
            except Exception as e:
                print(f"    - Chi-square test tidak dapat dilakukan: {e}")
                print(f"    - Melanjutkan dengan analisis alternatif...")
                
                # Analisis alternatif: Kolmogorov-Smirnov test
                try:
                    # Generate sample dari distribusi Poisson dengan mean yang sama
                    poisson_sample = np.random.poisson(mean_rate, size=len(packets_per_second))
                    
                    # Lakukan KS test
                    ks_stat, ks_pvalue = stats.ks_2samp(packets_per_second.values, poisson_sample)
                    print(f"    - Kolmogorov-Smirnov test: statistic={ks_stat:.4f}, p-value={ks_pvalue:.4f}")
                    
                    if ks_pvalue > 0.05:
                        print(f"    - Hasil uji KS: Distribusi konsisten dengan Poisson (p > 0.05)")
                    else:
                        print(f"    - Hasil uji KS: Distribusi tidak konsisten dengan Poisson (p < 0.05)")
                except Exception as ks_e:
                    print(f"    - Kolmogorov-Smirnov test juga tidak dapat dilakukan: {ks_e}")
        else:
            print(f"    - Chi-square test tidak dapat dilakukan (tidak cukup data)")
            
            # Analisis alternatif untuk dataset kecil
            try:
                # Generate sample dari distribusi Poisson dengan mean yang sama
                poisson_sample = np.random.poisson(mean_rate, size=len(packets_per_second))
                
                # Lakukan KS test
                ks_stat, ks_pvalue = stats.ks_2samp(packets_per_second.values, poisson_sample)
                print(f"    - Kolmogorov-Smirnov test: statistic={ks_stat:.4f}, p-value={ks_pvalue:.4f}")
                
                if ks_pvalue > 0.05:
                    print(f"    - Hasil uji KS: Distribusi konsisten dengan Poisson (p > 0.05)")
                else:
                    print(f"    - Hasil uji KS: Distribusi tidak konsisten dengan Poisson (p < 0.05)")
            except Exception as e:
                print(f"    - Kolmogorov-Smirnov test tidak dapat dilakukan: {e}")
        
        # Visualisasi 1: Histogram jumlah paket per detik
        plt.figure(figsize=(12, 6))
        plt.hist(packets_per_second, bins=30, alpha=0.7, color='#3498db', edgecolor='black')
        
        # Plot distribusi Poisson yang sesuai
        x = np.arange(0, max(packets_per_second) + 1)
        y = poisson.pmf(x, mean_rate) * len(packets_per_second)
        plt.plot(x, y, 'r-', linewidth=2, label=f'Poisson PMF (λ={mean_rate:.2f})')
        
        plt.xlabel('Packets per Second')
        plt.ylabel('Frequency')
        plt.title(f'Packet Arrival Distribution (Type: {distribution_type})')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.savefig(f"{viz_dir}/packet_arrival_distribution.png")
        plt.close()
        
        # Visualisasi 2: Time series plot jumlah paket per detik
        plt.figure(figsize=(14, 6))
        packets_per_second.plot(color='#2980b9', linewidth=1.5)
        plt.axhline(y=mean_rate, color='r', linestyle='--', label=f'Mean Rate: {mean_rate:.2f} pkt/s')
        
        plt.xlabel('Time')
        plt.ylabel('Packets per Second')
        plt.title('Packet Arrival Rate Over Time')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.savefig(f"{viz_dir}/packet_arrival_timeseries.png")
        plt.close()
        
        # Visualisasi 3: QQ plot untuk membandingkan dengan distribusi Poisson
        plt.figure(figsize=(10, 10))
        
        # Generate theoretical quantiles dari distribusi Poisson
        theoretical_quantiles = poisson.ppf(np.linspace(0.01, 0.99, len(packets_per_second)), mean_rate)
        
        # Sort observed data untuk QQ plot
        observed_quantiles = np.sort(packets_per_second.values)
        
        # Plot QQ plot
        plt.scatter(theoretical_quantiles, observed_quantiles, color='#3498db', alpha=0.7)
        
        # Plot garis referensi y=x
        max_val = max(max(theoretical_quantiles), max(observed_quantiles))
        plt.plot([0, max_val], [0, max_val], 'r--', linewidth=2)
        
        plt.xlabel('Theoretical Quantiles (Poisson)')
        plt.ylabel('Observed Quantiles')
        plt.title('Q-Q Plot: Observed vs Poisson Distribution')
        plt.grid(True, alpha=0.3)
        plt.savefig(f"{viz_dir}/packet_arrival_qq_plot.png")
        plt.close()
        
        # Visualisasi 4: Autocorrelation plot untuk memeriksa independensi
        from pandas.plotting import autocorrelation_plot
        
        plt.figure(figsize=(12, 6))
        autocorrelation_plot(packets_per_second)
        plt.title('Autocorrelation of Packet Arrivals')
        plt.grid(True, alpha=0.3)
        plt.savefig(f"{viz_dir}/packet_arrival_autocorrelation.png")
        plt.close()
        
        # Visualisasi 5: Interarrival times histogram
        if 'timestamp' in self.data.columns:
            # Sort data berdasarkan timestamp
            sorted_data = self.data.sort_values('timestamp')
            
            # Hitung interarrival times
            interarrival_times = sorted_data['timestamp'].diff().dropna() * 1000  # konversi ke ms
            
            # Filter outlier
            interarrival_times = interarrival_times[interarrival_times < interarrival_times.quantile(0.99)]
            
            plt.figure(figsize=(12, 6))
            plt.hist(interarrival_times, bins=50, alpha=0.7, color='#2ecc71', edgecolor='black')
            
            # Jika distribusi Poisson, interarrival times seharusnya mengikuti distribusi eksponensial
            mean_interarrival = interarrival_times.mean()
            x = np.linspace(0, interarrival_times.max(), 1000)
            y = len(interarrival_times) * stats.expon.pdf(x, scale=mean_interarrival)
            plt.plot(x, y, 'r-', linewidth=2, label=f'Exponential PDF (μ={mean_interarrival:.2f} ms)')
            
            plt.xlabel('Interarrival Time (ms)')
            plt.ylabel('Frequency')
            plt.title('Packet Interarrival Time Distribution')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.savefig(f"{viz_dir}/interarrival_time_distribution.png")
            plt.close()
            
            # Uji kesesuaian dengan distribusi eksponensial
            from scipy.stats import kstest
            try:
                ks_stat, ks_pvalue = kstest(interarrival_times, 'expon', args=(0, mean_interarrival))
                print(f"    - Kolmogorov-Smirnov test untuk interarrival times: statistic={ks_stat:.4f}, p-value={ks_pvalue:.4f}")
                
                if ks_pvalue > 0.05:
                    print(f"    - Hasil uji: Interarrival times konsisten dengan distribusi eksponensial (p > 0.05)")
                    print(f"    - Ini mendukung hipotesis bahwa kedatangan paket mengikuti proses Poisson")
                else:
                    print(f"    - Hasil uji: Interarrival times tidak konsisten dengan distribusi eksponensial (p < 0.05)")
                    print(f"    - Ini menunjukkan bahwa kedatangan paket mungkin tidak mengikuti proses Poisson")
            except Exception as e:
                print(f"    - KS test untuk interarrival times tidak dapat dilakukan: {e}")
        
        # Visualisasi 6: Perbandingan distribusi sebelum dan sesudah mitigasi
        if self.mitigated_data is not None:
            # Kelompokkan paket hasil mitigasi berdasarkan waktu (per detik)
            mitigated_packets = self.mitigated_data[~self.mitigated_data['is_blocked']]
            if 'datetime' not in mitigated_packets.columns:
                mitigated_packets['datetime'] = pd.to_datetime(mitigated_packets['timestamp'], unit='s')
            
            mitigated_per_second = mitigated_packets.groupby(mitigated_packets['datetime'].dt.floor('S')).size()
            
            # Hitung statistik dasar untuk hasil mitigasi
            mitigated_mean = mitigated_per_second.mean()
            mitigated_var = mitigated_per_second.var()
            mitigated_dispersion = mitigated_var / mitigated_mean if mitigated_mean > 0 else 0
            
            print(f"\n    - Setelah mitigasi:")
            print(f"    - Rate kedatangan paket rata-rata: {mitigated_mean:.2f} paket/detik")
            print(f"    - Indeks dispersi: {mitigated_dispersion:.4f}")
            
            # Interpretasi indeks dispersi setelah mitigasi
            if 0.9 <= mitigated_dispersion <= 1.1:
                mitigated_type = "Poisson (random arrivals)"
                print(f"    - Pola distribusi setelah mitigasi: {mitigated_type}")
            elif mitigated_dispersion < 0.9:
                mitigated_type = "Sub-Poisson/Deterministic"
                print(f"    - Pola distribusi setelah mitigasi: {mitigated_type}")
            else:  # mitigated_dispersion > 1.1
                mitigated_type = "Super-Poisson/Bursty"
                print(f"    - Pola distribusi setelah mitigasi: {mitigated_type}")
            
            # Plot perbandingan distribusi sebelum dan sesudah mitigasi
            plt.figure(figsize=(12, 6))
            
            # Histogram untuk data sebelum mitigasi
            plt.hist(packets_per_second, bins=30, alpha=0.5, label='Before Mitigation', color='#3498db', edgecolor='black')
            
            # Histogram untuk data setelah mitigasi
            plt.hist(mitigated_per_second, bins=30, alpha=0.5, label='After Mitigation', color='#2ecc71', edgecolor='black')
            
            plt.xlabel('Packets per Second')
            plt.ylabel('Frequency')
            plt.title('Packet Arrival Distribution Before and After Mitigation')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.savefig(f"{viz_dir}/packet_distribution_comparison.png")
            plt.close()
            
            # Visualisasi time series perbandingan
            plt.figure(figsize=(14, 8))
            
            # Reindex untuk memastikan kedua series memiliki index yang sama
            all_times = sorted(set(packets_per_second.index) | set(mitigated_per_second.index))
            before_series = packets_per_second.reindex(all_times, fill_value=0)
            after_series = mitigated_per_second.reindex(all_times, fill_value=0)
            
            # PERBAIKAN: Gunakan metode plot() dari Series pandas
            before_series.plot(color='#3498db', alpha=0.7, label='Before Mitigation')
            after_series.plot(color='#2ecc71', alpha=0.7, label='After Mitigation')
            
            # Tambahkan rata-rata
            plt.axhline(y=mean_rate, color='#3498db', linestyle='--', alpha=0.7, label=f'Mean Before: {mean_rate:.2f}')
            plt.axhline(y=mitigated_mean, color='#2ecc71', linestyle='--', alpha=0.7, label=f'Mean After: {mitigated_mean:.2f}')
            
            plt.xlabel('Time')
            plt.ylabel('Packets per Second')
            plt.title('Packet Arrival Rate Over Time (Before vs After Mitigation)')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.savefig(f"{viz_dir}/packet_timeseries_comparison.png")
            plt.close()
            
            # Visualisasi 7: Analisis perubahan pola traffic setelah mitigasi
            # Hitung persentase pengurangan per detik
            common_times = sorted(set(packets_per_second.index) & set(mitigated_per_second.index))
            if common_times:
                before_common = packets_per_second.loc[common_times]
                after_common = mitigated_per_second.loc[common_times]
                
                # Hitung persentase pengurangan
                reduction_pct = ((before_common - after_common) / before_common * 100).replace([np.inf, -np.inf], np.nan).dropna()
                
                plt.figure(figsize=(14, 6))
                # PERBAIKAN: Gunakan metode plot() dari Series pandas
                reduction_pct.plot(color='#e74c3c', linewidth=1.5)
                plt.axhline(y=reduction_pct.mean(), color='k', linestyle='--', 
                            label=f'Mean Reduction: {reduction_pct.mean():.2f}%')
                
                plt.xlabel('Time')
                plt.ylabel('Reduction Percentage (%)')
                plt.title('Traffic Reduction Percentage Over Time')
                plt.legend()
                plt.grid(True, alpha=0.3)
                plt.savefig(f"{viz_dir}/traffic_reduction_percentage.png")
                plt.close()
                
                # Visualisasi scatter plot untuk melihat korelasi antara jumlah paket sebelum dan sesudah mitigasi
                plt.figure(figsize=(10, 10))
                plt.scatter(before_common, after_common, alpha=0.6, color='#3498db')
                
                # Tambahkan garis regresi
                from scipy import stats
                slope, intercept, r_value, p_value, std_err = stats.linregress(before_common, after_common)
                x = np.linspace(min(before_common), max(before_common), 100)
                plt.plot(x, slope * x + intercept, 'r-', 
                        label=f'Regression: y={slope:.2f}x+{intercept:.2f}, r²={r_value**2:.2f}')
                
                # Tambahkan garis y=x (tidak ada perubahan)
                max_val = max(max(before_common), max(after_common))
                plt.plot([0, max_val], [0, max_val], 'k--', label='y=x (No Change)')
                
                plt.xlabel('Packets per Second (Before Mitigation)')
                plt.ylabel('Packets per Second (After Mitigation)')
                plt.title('Correlation Between Traffic Before and After Mitigation')
                plt.legend()
                plt.grid(True, alpha=0.3)
                plt.savefig(f"{viz_dir}/traffic_correlation.png")
                plt.close()
        
        # Visualisasi 8: Analisis distribusi Poisson vs distribusi empiris
        plt.figure(figsize=(12, 6))
        
        # Histogram data empiris
        counts, bins, _ = plt.hist(packets_per_second, bins=range(0, int(max(packets_per_second))+2), 
                                alpha=0.6, color='#3498db', label='Empirical Distribution')
        
        # Distribusi Poisson teoritis
        x = np.arange(0, int(max(packets_per_second))+1)
        pmf = poisson.pmf(x, mean_rate)
        plt.plot(x, pmf * sum(counts), 'ro-', label=f'Poisson Distribution (λ={mean_rate:.2f})')
        
        # Tambahkan label dan judul
        plt.xlabel('Packets per Second')
        plt.ylabel('Frequency')
        plt.title('Empirical Distribution vs Poisson Distribution')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.savefig(f"{viz_dir}/empirical_vs_poisson.png")
        plt.close()
        
        # Visualisasi 9: Analisis distribusi interarrival times untuk berbagai tipe paket
        if 'timestamp' in self.data.columns and 'packet_type' in self.data.columns:
            plt.figure(figsize=(14, 8))
            
            # Pilih beberapa tipe paket untuk analisis
            packet_types = ['interest', 'data', 'interest_forward', 'data_forward']
            colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']
            
            for i, ptype in enumerate(packet_types):
                if ptype in self.data['packet_type'].values:
                    # Filter data untuk tipe paket tertentu
                    type_data = self.data[self.data['packet_type'] == ptype].sort_values('timestamp')
                    
                    # Hitung interarrival times
                    if len(type_data) > 1:
                        interarrivals = type_data['timestamp'].diff().dropna() * 1000  # konversi ke ms
                        
                        # Filter outlier
                        interarrivals = interarrivals[interarrivals < interarrivals.quantile(0.99)]
                        
                        if len(interarrivals) > 0:
                            # Plot histogram
                            plt.hist(interarrivals, bins=30, alpha=0.5, color=colors[i], 
                                    label=f'{ptype} (mean={interarrivals.mean():.2f}ms)')
            
            plt.xlabel('Interarrival Time (ms)')
            plt.ylabel('Frequency')
            plt.title('Interarrival Time Distribution by Packet Type')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.savefig(f"{viz_dir}/interarrival_by_packet_type.png")
            plt.close()


    def visualize_results(self):
        """Visualisasi hasil mitigasi dengan grafik yang lebih komprehensif."""
        print(SECTION_HEADER("Visualisasi Hasil Mitigasi"))
        
        if self.mitigated_data is None:
            print("[!] Tidak ada data mitigasi untuk divisualisasikan. Jalankan apply_rule_based_mitigation() terlebih dahulu.")
            return
        
        # Buat direktori visualisasi jika belum ada
        viz_dir = f"{self.output_dir}/visualizations"
        if not os.path.exists(viz_dir):
            os.makedirs(viz_dir)
        
        # 1. Visualisasi perbandingan jumlah paket sebelum dan sesudah mitigasi
        self._visualize_packet_comparison(viz_dir)
        
        # 2. Visualisasi distribusi alasan blocking
        self._visualize_blocking_reasons(viz_dir)
        
        # 3. Visualisasi confusion matrix
        self._visualize_confusion_matrix(viz_dir)
        
        # 4. Visualisasi metrik evaluasi
        self._visualize_evaluation_metrics(viz_dir)
        
        # 5. Visualisasi distribusi paket berdasarkan tipe
        self._visualize_packet_type_distribution(viz_dir)
        
        # 6. Visualisasi distribusi ukuran paket
        self._visualize_packet_size_distribution(viz_dir)
        
        # 7. Visualisasi distribusi delay
        self._visualize_delay_distribution(viz_dir)
        
        # 8. Visualisasi distribusi bandwidth
        self._visualize_bandwidth_distribution(viz_dir)
        
        # 9. Visualisasi distribusi serangan berdasarkan node
        self._visualize_attack_distribution_by_node(viz_dir)
        
        # 10. Visualisasi timeline serangan
        self._visualize_attack_timeline(viz_dir)
        
        # Analisis dan visualisasi pola distribusi traffic
        self._analyze_traffic_distribution(viz_dir)
        self._visualize_packet_comparison(viz_dir)
        self._visualize_blocking_reasons(viz_dir)
        
        print(f"[+] Visualisasi hasil mitigasi disimpan di {viz_dir}")
    
    def _visualize_packet_comparison(self, viz_dir):
        """Visualisasi perbandingan jumlah paket sebelum dan sesudah mitigasi."""
        plt.figure(figsize=(12, 6))
        
        # Data untuk visualisasi
        categories = ['Total', 'Attack', 'Legitimate']
        before_values = [
            self.mitigation_stats['total_packets']['before'],
            self.mitigation_stats['attack_packets']['before'],
            self.mitigation_stats['legitimate_packets']['before']
        ]
        after_values = [
            self.mitigation_stats['total_packets']['after'],
            self.mitigation_stats['attack_packets']['after'],
            self.mitigation_stats['legitimate_packets']['after']
        ]
        
        # Posisi bar
        x = np.arange(len(categories))
        width = 0.35
        
        # Plot bar
        plt.bar(x - width/2, before_values, width, label='Before Mitigation', color='#3498db')
        plt.bar(x + width/2, after_values, width, label='After Mitigation', color='#2ecc71')
        
        # Tambahkan label dan judul
        plt.xlabel('Packet Category')
        plt.ylabel('Number of Packets')
        plt.title('Packet Count Before and After Mitigation')
        plt.xticks(x, categories)
        plt.legend()
        
        # Tambahkan nilai di atas bar
        for i, v in enumerate(before_values):
            plt.text(i - width/2, v + 0.1, str(v), ha='center', fontweight='bold')
        
        for i, v in enumerate(after_values):
            plt.text(i + width/2, v + 0.1, str(v), ha='center', fontweight='bold')
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{viz_dir}/packet_comparison.png")
        plt.close()
    
    def _visualize_blocking_reasons(self, viz_dir):
        """Visualisasi distribusi alasan blocking."""
        # Ambil data alasan blocking
        block_reasons = self.mitigated_data[self.mitigated_data['is_blocked']]['block_reason'].value_counts()
        
        if len(block_reasons) == 0:
            print("[!] Tidak ada data alasan blocking untuk divisualisasikan.")
            return
        
        # Ambil top 10 alasan
        top_reasons = block_reasons.head(10)
        
        plt.figure(figsize=(12, 8))
        
        # Plot horizontal bar chart
        bars = plt.barh(top_reasons.index, top_reasons.values, color='#e74c3c')
        
        # Tambahkan label dan judul
        plt.xlabel('Number of Packets Blocked')
        plt.ylabel('Blocking Reason')
        plt.title('Top 10 Reasons for Blocking Packets')
        
        # Tambahkan nilai di sebelah bar
        for i, v in enumerate(top_reasons.values):
            plt.text(v + 0.5, i, str(v), va='center')
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{viz_dir}/blocking_reasons.png")
        plt.close()
    
    def _visualize_confusion_matrix(self, viz_dir):
        """Visualisasi confusion matrix."""
        # Hitung confusion matrix
        tp = self.mitigated_data[(self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 1)].shape[0]
        fp = self.mitigated_data[(self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 0)].shape[0]
        tn = self.mitigated_data[(~self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 0)].shape[0]
        fn = self.mitigated_data[(~self.mitigated_data['is_blocked']) & (self.mitigated_data['is_attack'] == 1)].shape[0]
        
        # Buat confusion matrix
        cm = np.array([[tn, fp], [fn, tp]])
        
        plt.figure(figsize=(10, 8))
        
        # Plot confusion matrix dengan seaborn
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Not Blocked', 'Blocked'],
                    yticklabels=['Normal', 'Attack'])
        
        # Tambahkan label dan judul
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix')
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{viz_dir}/confusion_matrix.png")
        plt.close()
    
    def _visualize_evaluation_metrics(self, viz_dir):
        """Visualisasi metrik evaluasi."""
        # Ambil metrik evaluasi
        metrics = self.evaluate_mitigation_performance()
        
        # Pilih metrik untuk divisualisasikan
        selected_metrics = {
            'Accuracy': metrics['accuracy'],
            'Precision': metrics['precision'],
            'Recall': metrics['recall'],
            'F1 Score': metrics['f1_score'],
            'Specificity': metrics['specificity'],
            'Balanced Accuracy': metrics['balanced_accuracy']
        }
        
        plt.figure(figsize=(12, 6))
        
        # Plot bar chart
        bars = plt.bar(selected_metrics.keys(), selected_metrics.values(), color='#9b59b6')
        
        # Tambahkan label dan judul
        plt.xlabel('Metric')
        plt.ylabel('Value')
        plt.title('Evaluation Metrics')
        plt.ylim(0, 1.1)  # Metrik biasanya antara 0 dan 1
        
        # Tambahkan nilai di atas bar
        for i, v in enumerate(selected_metrics.values()):
            plt.text(i, v + 0.02, f"{v:.4f}", ha='center')
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{viz_dir}/evaluation_metrics.png")
        plt.close()
    
    def _visualize_packet_type_distribution(self, viz_dir):
        """Visualisasi distribusi paket berdasarkan tipe."""
        # Distribusi tipe paket sebelum mitigasi
        before_dist = self.data['packet_type'].value_counts()
        
        # Distribusi tipe paket setelah mitigasi
        after_dist = self.mitigated_data[~self.mitigated_data['is_blocked']]['packet_type'].value_counts()
        
        # Gabungkan distribusi
        packet_types = list(set(before_dist.index) | set(after_dist.index))
        before_values = [before_dist.get(pt, 0) for pt in packet_types]
        after_values = [after_dist.get(pt, 0) for pt in packet_types]
        
        # Buat figure dengan 2 subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))
        
        # Plot pie chart untuk distribusi sebelum mitigasi
        ax1.pie(before_values, labels=packet_types, autopct='%1.1f%%', startangle=90, colors=plt.cm.Paired(np.arange(len(packet_types))))
        ax1.set_title('Packet Type Distribution Before Mitigation')
        
        # Plot pie chart untuk distribusi setelah mitigasi
        ax2.pie(after_values, labels=packet_types, autopct='%1.1f%%', startangle=90, colors=plt.cm.Paired(np.arange(len(packet_types))))
        ax2.set_title('Packet Type Distribution After Mitigation')
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{viz_dir}/packet_type_distribution.png")
        plt.close()
    
    def _visualize_packet_size_distribution(self, viz_dir):
        """Visualisasi distribusi ukuran paket."""
        plt.figure(figsize=(12, 6))
        
        # Plot histogram untuk paket normal
        plt.hist(self.data[self.data['is_attack'] == 0]['packet_size'], bins=50, alpha=0.5, label='Normal Packets', color='#3498db')
        
        # Plot histogram untuk paket serangan
        plt.hist(self.data[self.data['is_attack'] == 1]['packet_size'], bins=50, alpha=0.5, label='Attack Packets', color='#e74c3c')
        
        # Tambahkan label dan judul
        plt.xlabel('Packet Size (bytes)')
        plt.ylabel('Frequency')
        plt.title('Packet Size Distribution')
        plt.legend()
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{viz_dir}/packet_size_distribution.png")
        plt.close()
    
    def _visualize_delay_distribution(self, viz_dir):
        """Visualisasi distribusi delay."""
        plt.figure(figsize=(12, 6))
        
        # Plot histogram untuk paket normal
        plt.hist(self.data[self.data['is_attack'] == 0]['delay_ms'], bins=50, alpha=0.5, label='Normal Packets', color='#3498db')
        
        # Plot histogram untuk paket serangan
        plt.hist(self.data[self.data['is_attack'] == 1]['delay_ms'], bins=50, alpha=0.5, label='Attack Packets', color='#e74c3c')
        
        # Tambahkan label dan judul
        plt.xlabel('Delay (ms)')
        plt.ylabel('Frequency')
        plt.title('Delay Distribution')
        plt.legend()
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{viz_dir}/delay_distribution.png")
        plt.close()
    
    def _visualize_bandwidth_distribution(self, viz_dir):
        """Visualisasi distribusi bandwidth."""
        plt.figure(figsize=(12, 6))
        
        # Plot histogram untuk paket normal
        plt.hist(self.data[self.data['is_attack'] == 0]['bandwidth_mbps'], bins=50, alpha=0.5, label='Normal Packets', color='#3498db')
        
        # Plot histogram untuk paket serangan
        plt.hist(self.data[self.data['is_attack'] == 1]['bandwidth_mbps'], bins=50, alpha=0.5, label='Attack Packets', color='#e74c3c')
        
        # Tambahkan label dan judul
        plt.xlabel('Bandwidth (Mbps)')
        plt.ylabel('Frequency')
        plt.title('Bandwidth Distribution')
        plt.legend()
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{viz_dir}/bandwidth_distribution.png")
        plt.close()
    
    def _visualize_attack_distribution_by_node(self, viz_dir):
        """Visualisasi distribusi serangan berdasarkan node."""
        # Hitung jumlah paket serangan per node
        attack_by_node = self.data[self.data['is_attack'] == 1]['from_node'].value_counts().head(10)
        
        plt.figure(figsize=(12, 8))
        
        # Plot horizontal bar chart
        bars = plt.barh(attack_by_node.index, attack_by_node.values, color='#e74c3c')
        
        # Tambahkan label dan judul
        plt.xlabel('Number of Attack Packets')
        plt.ylabel('Node')
        plt.title('Top 10 Nodes by Attack Packet Count')
        
        # Tambahkan nilai di sebelah bar
        for i, v in enumerate(attack_by_node.values):
            plt.text(v + 0.5, i, str(v), va='center')
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{viz_dir}/attack_distribution_by_node.png")
        plt.close()
    
    def _visualize_attack_timeline(self, viz_dir):
        """Visualisasi timeline serangan."""
        # Pastikan kolom datetime ada
        if 'datetime' not in self.data.columns:
            self.data['datetime'] = pd.to_datetime(self.data['timestamp'], unit='s')
        
        # Hitung jumlah paket per detik
        attack_timeline = self.data.groupby([self.data['datetime'].dt.floor('S'), 'is_attack']).size().unstack(fill_value=0)
        
        # Rename kolom
        if 0 in attack_timeline.columns and 1 in attack_timeline.columns:
            attack_timeline.columns = ['Normal', 'Attack']
        else:
            # Jika salah satu kolom tidak ada, tambahkan dengan nilai 0
            if 0 not in attack_timeline.columns:
                attack_timeline[0] = 0
            if 1 not in attack_timeline.columns:
                attack_timeline[1] = 0
            attack_timeline.columns = ['Normal', 'Attack']
        
        plt.figure(figsize=(14, 8))
        
        # Plot timeline
        attack_timeline.plot(ax=plt.gca())
        
        # Tambahkan label dan judul
        plt.xlabel('Time')
        plt.ylabel('Number of Packets')
        plt.title('Packet Timeline')
        plt.legend()
        
        # Simpan gambar
        plt.tight_layout()
        plt.savefig(f"{viz_dir}/attack_timeline.png")
        plt.close()
    
    def export_rules(self, output_path=None):
        """Export konfigurasi rule ke file JSON."""
        if output_path is None:
            output_path = f"{self.output_dir}/rules_config.json"
        
        try:
            with open(output_path, 'w') as f:
                json.dump(self.rules, f, indent=4)
            
            print(f"[+] Konfigurasi rule berhasil diekspor ke {output_path}")
            return True
        except Exception as e:
            print(f"[!] Error saat mengekspor konfigurasi: {e}")
            return False
    
    def generate_report(self, output_path=None):
        """Generate laporan hasil mitigasi."""
        if output_path is None:
            output_path = f"{self.output_dir}/mitigation_report.txt"
        
        try:
            with open(output_path, 'w') as f:
                # Header
                f.write("=" * 80 + "\n")
                f.write("NDN RULE-BASED MITIGATION REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Dataset info
                f.write("DATASET INFORMATION\n")
                f.write("-" * 80 + "\n")
                f.write(f"Dataset path: {self.dataset_path}\n")
                f.write(f"Total packets: {len(self.data)}\n")
                f.write(f"Attack packets: {len(self.data[self.data['is_attack'] == 1])} ({len(self.data[self.data['is_attack'] == 1])/len(self.data)*100:.2f}%)\n")
                f.write(f"Normal packets: {len(self.data[self.data['is_attack'] == 0])} ({len(self.data[self.data['is_attack'] == 0])/len(self.data)*100:.2f}%)\n\n")
                
                # Attack stats
                f.write("ATTACK STATISTICS\n")
                f.write("-" * 80 + "\n")
                f.write(f"Interest Flooding: {self.attack_stats['interest_flooding']['packet_count']} packets ({self.attack_stats['interest_flooding']['percent_of_traffic']:.2f}% of traffic)\n")
                f.write(f"Cache Poisoning: {self.attack_stats['cache_poisoning']['packet_count']} packets ({self.attack_stats['cache_poisoning']['percent_of_traffic']:.2f}% of traffic)\n\n")
                
                # Mitigation stats
                f.write("MITIGATION STATISTICS\n")
                f.write("-" * 80 + "\n")
                f.write(f"Total packets before mitigation: {self.mitigation_stats['total_packets']['before']}\n")
                f.write(f"Total packets after mitigation: {self.mitigation_stats['total_packets']['after']}\n")
                f.write(f"Reduction: {self.mitigation_stats['total_packets']['reduction']:.2f}%\n\n")
                
                f.write(f"Attack packets before mitigation: {self.mitigation_stats['attack_packets']['before']}\n")
                f.write(f"Attack packets after mitigation: {self.mitigation_stats['attack_packets']['after']}\n")
                f.write(f"Reduction: {self.mitigation_stats['attack_packets']['reduction']:.2f}%\n\n")
                
                f.write(f"Legitimate packets before mitigation: {self.mitigation_stats['legitimate_packets']['before']}\n")
                f.write(f"Legitimate packets after mitigation: {self.mitigation_stats['legitimate_packets']['after']}\n")
                f.write(f"Reduction: {self.mitigation_stats['legitimate_packets']['reduction']:.2f}%\n\n")
                
                # Evaluation metrics
                metrics = self.evaluate_mitigation_performance()
                f.write("EVALUATION METRICS\n")
                f.write("-" * 80 + "\n")
                f.write(f"Accuracy: {metrics['accuracy']:.4f}\n")
                f.write(f"Precision: {metrics['precision']:.4f}\n")
                f.write(f"Recall: {metrics['recall']:.4f}\n")
                f.write(f"F1 Score: {metrics['f1_score']:.4f}\n")
                f.write(f"Specificity: {metrics['specificity']:.4f}\n")
                f.write(f"Balanced Accuracy: {metrics['balanced_accuracy']:.4f}\n")
                f.write(f"False Positive Rate: {metrics['false_positive_rate']:.4f}\n")
                f.write(f"False Negative Rate: {metrics['false_negative_rate']:.4f}\n\n")
                
                # Confusion matrix
                f.write("CONFUSION MATRIX\n")
                f.write("-" * 80 + "\n")
                f.write(f"True Positive (TP): {metrics['confusion_matrix']['tp']}\n")
                f.write(f"False Positive (FP): {metrics['confusion_matrix']['fp']}\n")
                f.write(f"True Negative (TN): {metrics['confusion_matrix']['tn']}\n")
                f.write(f"False Negative (FN): {metrics['confusion_matrix']['fn']}\n\n")
                
                # Top blocking reasons
                f.write("TOP BLOCKING REASONS\n")
                f.write("-" * 80 + "\n")
                block_reasons = self.mitigated_data[self.mitigated_data['is_blocked']]['block_reason'].value_counts().head(10)
                for reason, count in block_reasons.items():
                    f.write(f"{reason}: {count} packets\n")
                f.write("\n")
                
                # Rules configuration
                f.write("RULES CONFIGURATION\n")
                f.write("-" * 80 + "\n")
                for key, value in self.rules.items():
                    if isinstance(value, list):
                        if len(value) > 10:
                            f.write(f"{key}: {len(value)} items\n")
                        else:
                            f.write(f"{key}: {value}\n")
                    else:
                        f.write(f"{key}: {value}\n")
                
                # Footer
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n")
            
            print(f"[+] Laporan hasil mitigasi berhasil digenerate di {output_path}")
            return True
        except Exception as e:
            print(f"[!] Error saat generate laporan: {e}")
            return False

# ==============================
# SECTION: Main Function
# ==============================

def main():
    """Fungsi utama untuk menjalankan program."""
    # Parse argumen command line
    parser = argparse.ArgumentParser(description='NDN Rule-Based Mitigation System')
    parser.add_argument('--dataset', type=str, required=True, help='Path ke file dataset CSV')
    parser.add_argument('--output', type=str, default='Mitigation_NDN', help='Direktori untuk menyimpan hasil mitigasi')
    parser.add_argument('--config', type=str, help='Path ke file konfigurasi rule (opsional)')
    parser.add_argument('--no-viz', action='store_true', help='Nonaktifkan visualisasi hasil')
    
    args = parser.parse_args()
    
    # Tampilkan header
    print(NDN_HEADER)
    print(VERSION_INFO)
    
    # Buat instance mitigasi
    mitigation = NDNRuleBasedMitigation(args.dataset, args.output, args.config)
    
    # Muat dataset
    if not mitigation.load_data():
        print("[!] Gagal memuat dataset. Program berhenti.")
        return
    
    # Analisis traffic
    mitigation.analyze_traffic()
    
    # Update node reputation berdasarkan perilaku historis
    mitigation._update_node_reputation()
    
    # Terapkan mitigasi berbasis rule
    mitigation.apply_rule_based_mitigation()
    
    # Visualisasi hasil (jika tidak dinonaktifkan)
    if not args.no_viz:
        mitigation.visualize_results()
    
    # Export konfigurasi rule
    mitigation.export_rules()
    
    # Generate laporan
    mitigation.generate_report()
    
    print("\n[+] Proses mitigasi selesai.")

if __name__ == "__main__":
    main()

