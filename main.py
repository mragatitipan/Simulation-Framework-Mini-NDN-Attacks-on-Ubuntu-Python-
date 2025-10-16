#!/usr/bin/env python3
# ndn_simulation.py - Simulasi jaringan NDN untuk Telkom University

import time
import threading
import pandas as pd
import os
import sys
import argparse
import subprocess
import socket
import signal
import random
import datetime
from collections import defaultdict, deque
from datetime import datetime

# ==============================
# SECTION: Library Imports
# ==============================

# Import komponen NDN yang sebenarnya
try:
    from mininet.log import setLogLevel, info
    from mininet.topo import Topo  
    from minindn.minindn import Minindn
    from minindn.util import MiniNDNCLI
    from minindn.apps.app_manager import AppManager
    from minindn.apps.nfd import Nfd
    from minindn.apps.nlsr import Nlsr
    from minindn.helpers.nfdc import Nfdc
    MININDN_AVAILABLE = True
except ImportError:
    print("MiniNDN tidak tersedia. Simulasi akan berjalan dalam mode standalone.")
    MININDN_AVAILABLE = False

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
║ [*] Version: 1.2.3                                                               ║
║ [*] Codename: NDNSecure                                                          ║
║ [*] Author: Muhammad Raga Titipan (201012310022)                                 ║
║ [*] License: MIT                                                                 ║
║ [*] Build: 20250803-2134                                                         ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

# Referensi metode dan implementasi
REFERENCES = """
╔══════════════════════════════════════════════════════════════════════════════════╗
║                              [RESEARCH REFERENCES]                               ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ [R1] Zhang, L., et al. (2014). "Named Data Networking (NDN) Project."            ║
║     Technical Report NDN-0001, NDN.                                              ║
║                                                                                  ║
║ [R2] Afanasyev, A., et al. (2018). "NFD Developer's Guide."                      ║
║     https://named-data.net/publications/techreports/nfd-developer-guide/         ║
║                                                                                  ║
║ [R3] Yi, C., et al. (2013). "A Case for Stateful Forwarding Plane."              ║
║     Computer Communications, vol. 36, no. 7, pp. 779-791.                        ║
║                                                                                  ║
║ [R4] Gasti, P., et al. (2013). "DoS and DDoS in Named Data Networking."          ║
║     In Proc. of IEEE ICCCN 2013, pp. 1-7.                                        ║
║                                                                                  ║
║ [R5] Compagno, A., et al. (2013). "Poseidon: Mitigating Interest Flooding DDoS   ║
║     Attacks in Named Data Networking." In Proc. of IEEE LCN 2013, pp. 630-638.   ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

# Section headers for terminal output
SECTION_HEADER = lambda title: f"""
╔═{'═' * (len(title) + 8)}═╗
║ {title.upper()} {' ' * (6 - len(title) % 6)}║
╚═{'═' * (len(title) + 8)}═╝
"""

# Penjelasan model serangan
ATTACK_MODELS = """
╔══════════════════════════════════════════════════════════════════════════════════╗
║                            [SECURITY THREAT MODELS]                              ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ [1] Interest Flooding Attack (IFA)                                               ║
║    ├─ Vector: Network saturation via excessive interest packets                  ║
║    ├─ Target: PIT (Pending Interest Table) resources in routers                  ║
║    ├─ Implementation: External nodes sending non-existent content requests       ║
║    └─ Reference: Gasti et al. [R4], Compagno et al. [R5]                         ║
║                                                                                  ║
║ [2] Cache Poisoning Attack (CPA)                                                 ║
║    ├─ Vector: Content integrity compromise via malicious data injection          ║
║    ├─ Target: Data integrity and availability in Content Store                   ║
║    ├─ Implementation: Nodes sending falsified content with valid naming          ║
║    └─ Reference: Ghali et al. "Network-Layer Trust in Named-Data Networking"     ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

# Penjelasan komponen NDN
NDN_COMPONENTS = """
╔══════════════════════════════════════════════════════════════════════════════════╗
║                           [NDN CORE COMPONENTS]                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ [CS] Content Store                                                               ║
║    ├─ Function: In-network caching system for Data packets                       ║
║    ├─ Purpose: Reduce latency and network traffic                                ║
║    └─ Security: Vulnerable to content poisoning                                  ║
║                                                                                  ║
║ [PIT] Pending Interest Table                                                     ║
║    ├─ Function: Tracks unsatisfied Interest packets                              ║
║    ├─ Purpose: Enables Interest aggregation and Data multicast                   ║
║    └─ Security: Vulnerable to resource exhaustion                                ║
║                                                                                  ║
║ [FIB] Forwarding Information Base                                                ║
║    ├─ Function: Stores routing information for Interest forwarding               ║
║    ├─ Purpose: Similar to routing tables in IP networks                          ║
║    └─ Security: Vulnerable to prefix hijacking                                   ║
║                                                                                  ║
║ [FACE] Communication Interfaces                                                  ║
║    ├─ Function: Abstraction for communication channels                           ║
║    ├─ Purpose: Represents physical interfaces or virtual connections             ║
║    └─ Security: Entry point for network attacks                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

# Topology visualization header
TOPOLOGY_HEADER = """
╔══════════════════════════════════════════════════════════════════════════════════╗
║                              NETWORK TOPOLOGY                                    ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║                       Producer (p_lib)                                           ║
║                            │                                                     ║
║                            ▼                                                     ║
║                       Router (r_fif) ◄────► Router (r_fit)                      ║
║                            │                    │                                ║
║                            │                    │                                ║
║                            ▼                    ▼                               ║
║                       Router (r_feb)         Consumer (c_std)                    ║
║                            │                    │                                ║
║                            ▼                    ▼                               ║
║                       Router (r_fkb)         Attacker (a_int)                    ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

# ==============================
# SECTION: Konstanta Global
# ==============================
# Definisi variabel global
OUTPUT_DIR = "./Test5"
SIMULATION_DURATION = 300
DATASET_FILE = "ndn_simulation_dataset.csv"
PCAP_FILE = "ndn_simulation_capture.pcap"

# Struktur direktori output
OUTPUT_STRUCTURE = {
    'raw_data': ['node_activity_logs.csv', 'ndn_traffic_capture.pcap'],
    'statistics': ['router_stats.csv', 'consumer_stats.csv', 'producer_stats.csv', 'attacker_stats.csv', 'face_stats.csv'],
    'dataset': ['traffic_dataset.csv'],
    'analysis': []  # Untuk hasil analisis nantinya
}

# ==============================
# SECTION: Definisi Konten
# ==============================

# Prefix konten yang tersedia (5 konten tetap)
CONTENT_PREFIXES = [
    "/ndn/telkom_university/akademik",
    "/ndn/telkom_university/penelitian",
    "/ndn/telkom_university/perpustakaan",
    "/ndn/telkom_university/strategis",
    "/ndn/telkom_university/repository"
]

# Definisi konten spesifik untuk setiap prefix dengan ukuran maksimal 8KB
CONTENT_CATALOG = {
    "/ndn/telkom_university/akademik": [
        {"name": "jadwal_kuliah", "size": 6144},      # 6KB
        {"name": "nilai_mahasiswa", "size": 8192},    # 8KB
        {"name": "kalender_akademik", "size": 5120},  # 5KB
        {"name": "kurikulum", "size": 7168},          # 7KB
        {"name": "info_wisuda", "size": 6656}         # 6.5KB
    ],
    "/ndn/telkom_university/penelitian": [
        {"name": "jurnal_teknik", "size": 8192},      # 8KB
        {"name": "paper_informatika", "size": 7680},  # 7.5KB
        {"name": "laporan_riset", "size": 8192},      # 8KB
        {"name": "publikasi_dosen", "size": 7168},    # 7KB
        {"name": "data_penelitian", "size": 8192}     # 8KB
    ],
    "/ndn/telkom_university/perpustakaan": [
        {"name": "katalog_buku", "size": 7680},       # 7.5KB
        {"name": "e_book", "size": 8192},             # 8KB
        {"name": "jurnal_internasional", "size": 8192}, # 8KB
        {"name": "skripsi_mahasiswa", "size": 7936},  # 7.75KB
        {"name": "majalah_ilmiah", "size": 7168}      # 7KB
    ],
    "/ndn/telkom_university/strategis": [
        {"name": "rencana_strategis", "size": 7168},  # 7KB
        {"name": "laporan_tahunan", "size": 8192},    # 8KB
        {"name": "profil_universitas", "size": 7680}, # 7.5KB
        {"name": "kerjasama_industri", "size": 6656}, # 6.5KB
        {"name": "statistik_kampus", "size": 7168}    # 7KB
    ],
    "/ndn/telkom_university/repository": [
        {"name": "repository_tugas_akhir", "size": 8192}, # 8KB
        {"name": "repository_jurnal", "size": 8192},      # 8KB
        {"name": "repository_buku", "size": 8192},        # 8KB
        {"name": "repository_materi", "size": 8192},      # 8KB
        {"name": "repository_media", "size": 8192}        # 8KB
    ]
}

# ==============================
# SECTION: Penjelasan Model Serangan
# ==============================

# Penjelasan model serangan
ATTACK_MODELS = """
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                               MODEL SERANGAN NDN                                  ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║ 1. Interest Flooding Attack (IFA)                                                 ║
║    - Penyerang mengirimkan banyak Interest dengan nama yang tidak ada             ║
║    - Tujuan: Menghabiskan resource PIT di router                                  ║
║    - Implementasi: Attacker dengan prefix 'a_ext' mengirim Interest nonexistent   ║
║    - Referensi: Gasti et al. [4], Compagno et al. [5]                            ║
║                                                                                   ║
║ 2. Cache Poisoning Attack (CPA)                                                   ║
║    - Penyerang mengirimkan data palsu untuk meracuni Content Store                ║
║    - Tujuan: Menyebarkan informasi palsu ke konsumen lain                         ║
║    - Implementasi: Attacker dengan prefix 'a_int' mengirim data palsu             ║
║    - Referensi: Ghali et al. "Network-Layer Trust in Named-Data Networking"       ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
"""

# Penjelasan komponen NDN
NDN_COMPONENTS = """
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                             KOMPONEN UTAMA NDN                                    ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║ 1. Content Store (CS)                                                             ║
║    - Cache untuk menyimpan Data packets                                           ║
║    - Meningkatkan efisiensi jaringan dengan mengurangi latensi dan traffic        ║
║                                                                                   ║
║ 2. Pending Interest Table (PIT)                                                   ║
║    - Menyimpan Interest yang belum terjawab                                       ║
║    - Memungkinkan agregasi Interest dan multicast Data                            ║
║                                                                                   ║
║ 3. Forwarding Information Base (FIB)                                              ║
║    - Menyimpan informasi routing untuk meneruskan Interest                        ║
║    - Mirip dengan routing table di jaringan IP                                    ║
║                                                                                   ║
║ 4. Faces                                                                          ║
║    - Abstraksi untuk interface komunikasi                                         ║
║    - Dapat berupa interface fisik atau koneksi virtual                            ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
"""

# ==============================
# SECTION: Definisi Kelas
# ==============================

class NDNFace:
    """Representasi Face di NDN menggunakan komponen NDN yang sebenarnya"""
    
    def __init__(self, face_id, remote_node_id, delay, bandwidth):
        self.face_id = face_id
        self.remote_node_id = remote_node_id
        self.delay = delay  # dalam ms
        self.bandwidth = float(bandwidth)  # dalam Mbps
        self.packets_in = 0
        self.packets_out = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.creation_time = time.time()
        self.last_active = time.time()
        # Tambahkan referensi ke objek Face dari NFD yang sebenarnya
        self.nfd_face = None
    
    def transmit_packet(self, size_bytes):
        """Simulasi transmisi paket melalui face ini"""
        self.packets_out += 1
        self.bytes_out += size_bytes
        self.last_active = time.time()
        
        # Hitung delay transmisi berdasarkan ukuran paket dan bandwidth
        # Delay = (ukuran paket dalam bits) / (bandwidth dalam bps)
        transmission_delay = (size_bytes * 8) / (self.bandwidth * 1000000)
        
        # Tambahkan delay propagasi (dari parameter delay)
        propagation_delay = float(self.delay.replace('ms', '')) / 1000
        
        # Total delay
        total_delay = transmission_delay + propagation_delay
        
        return total_delay
    
    def receive_packet(self, size_bytes):
        """Simulasi penerimaan paket melalui face ini"""
        self.packets_in += 1
        self.bytes_in += size_bytes
        self.last_active = time.time()
    
    def get_stats(self):
        """Mendapatkan statistik face"""
        uptime = time.time() - self.creation_time
        return {
            'face_id': self.face_id,
            'remote_node': self.remote_node_id,
            'delay': self.delay,
            'bandwidth': self.bandwidth,
            'packets_in': self.packets_in,
            'packets_out': self.packets_out,
            'bytes_in': self.bytes_in,
            'bytes_out': self.bytes_out,
            'uptime': uptime,
            'last_active': time.time() - self.last_active
        }


class NDNNode:
    """Kelas dasar untuk semua node dalam jaringan NDN"""
    
    def __init__(self, node_id, node_type, network_prefix):
        self.node_id = node_id
        self.node_type = node_type
        self.network_prefix = network_prefix
        self.links = {}  # {node_id: {'delay': delay, 'bandwidth': bandwidth, 'face_id': face_id}}
        self.faces = {}  # {face_id: NDNFace}
        self.next_face_id = 1
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = time.time()
        self.log_entries = []
        
        # Tambahkan referensi ke node MiniNDN yang sebenarnya
        self.mininet_node = None
        # Tambahkan referensi ke NFD yang berjalan di node ini
        self.nfd = None
    
    def add_link(self, remote_node_id, delay, bandwidth):
        """Menambahkan link ke node lain"""
        face_id = self.next_face_id
        self.next_face_id += 1
        
        self.links[remote_node_id] = {
            'delay': delay,
            'bandwidth': bandwidth,
            'face_id': face_id
        }
        
        self.faces[face_id] = NDNFace(face_id, remote_node_id, delay, bandwidth)
        
        return face_id
    
    def log_activity(self, activity_type, details, is_attack=False):
        """Mencatat aktivitas node untuk analisis"""
        timestamp = time.time()
        entry = {
            'timestamp': timestamp,
            'node_id': self.node_id,
            'node_type': self.node_type,
            'activity': activity_type,
            'details': details,
            'is_attack': 1 if is_attack else 0
        }
        self.log_entries.append(entry)
    
    def get_node_stats(self):
        """Mendapatkan statistik node"""
        uptime = time.time() - self.start_time
        return {
            'node_id': self.node_id,
            'node_type': self.node_type,
            'network_prefix': self.network_prefix,
            'links_count': len(self.links),
            'faces_count': len(self.faces),
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'uptime': uptime
        }
    
    def get_face_stats(self):
        """Mendapatkan statistik semua face"""
        return {face_id: face.get_stats() for face_id, face in self.faces.items()}


class NDNRouter(NDNNode):
    """Router NDN yang memproses Interest dan Data menggunakan NFD"""
    
    def __init__(self, node_id, network_prefix):
        super().__init__(node_id, 'router', network_prefix)
        # Dalam implementasi sebenarnya, PIT, FIB, dan CS dikelola oleh NFD
        # Kita simpan referensi untuk kompatibilitas dengan kode yang sudah ada
        self.pit = {}  # Pending Interest Table
        self.fib = {}  # Forwarding Information Base
        self.cs = {}   # Content Store
        self.cs_max_size = 100  # Ukuran maksimum Content Store (dalam jumlah entri)
        self.pit_max_size = 1000  # Ukuran maksimum PIT (dalam jumlah entri)
        self.pit_entry_timeout = 4.0  # Timeout untuk PIT entry (dalam detik)
        self.cs_hit_count = 0
        self.cs_miss_count = 0
        self.pit_expiry_count = 0
        self.pit_satisfaction_count = 0
        self.cpu_util = 0.0
        self.memory_util = 0.0
        self.last_cpu_update = time.time()
        
        # Tambahkan referensi ke NFD yang berjalan di router ini
        self.nfd_process = None
        # Tambahkan referensi ke NLSR yang berjalan di router ini
        self.nlsr_process = None
    
    def update_fib(self, prefix, next_hop, face_id, cost=10):
        """Memperbarui FIB dengan entri baru atau yang sudah ada"""
        # Dalam implementasi sebenarnya, ini akan memanggil nfdc route add
        if prefix not in self.fib:
            self.fib[prefix] = []
        
        # Cek apakah entri untuk next_hop ini sudah ada
        for entry in self.fib[prefix]:
            if entry['next_hop'] == next_hop:
                entry['face_id'] = face_id
                entry['cost'] = cost
                return
        
        # Tambahkan entri baru
        self.fib[prefix].append({
            'next_hop': next_hop,
            'face_id': face_id,
            'cost': cost
        })
        
        # Urutkan berdasarkan cost (terendah dulu)
        self.fib[prefix].sort(key=lambda x: x['cost'])
        
        # Jika node mininet dan nfd sudah ada, gunakan nfdc untuk menambahkan rute
        if self.mininet_node and self.nfd_process:
            try:
                # Dalam implementasi sebenarnya, ini akan memanggil nfdc route add
                # Nfdc.registerRoute(self.mininet_node, prefix, next_hop, cost)
                pass
            except Exception as e:
                print(f"Error updating FIB with NFD: {e}")
    
    def find_matching_fib_entry(self, interest_name):
        """Menemukan entri FIB yang cocok dengan Interest"""
        # Coba semua kemungkinan prefix dari yang terpanjang ke terpendek
        parts = interest_name.split('/')
        for i in range(len(parts), 0, -1):
            prefix = '/'.join(parts[:i])
            if prefix in self.fib and self.fib[prefix]:
                return self.fib[prefix][0]  # Ambil entri dengan cost terendah
        
        return None
    
    def receive_interest(self, interest_name, from_node, face_id, is_attack=False):
        """Menerima dan memproses Interest"""
        # Update statistik
        self.packet_count += 1
        interest_size = len(interest_name) + 40  # Estimasi ukuran packet
        self.byte_count += interest_size
        
        # Update face
        if face_id in self.faces:
            self.faces[face_id].receive_packet(interest_size)
        
        # Perbarui CPU utilization
        self.update_cpu_util()
        
        # Log aktivitas
        activity = 'interest_received'
        if is_attack:
            activity = 'attack_interest_received'
        
        detail_str = (f"Interest: {interest_name}, From: {from_node}, "
                     f"face_id: {face_id}, PIT_size: {len(self.pit)}, "
                     f"CPU: {self.cpu_util:.2f}%, Memory: {self.memory_util:.2f}%")
        
        self.log_activity(activity, detail_str, is_attack)
        
        # Cek Content Store terlebih dahulu
        if interest_name in self.cs:
            # CS hit - kirim data langsung kembali
            self.cs_hit_count += 1
            cs_hit_ratio = self.cs_hit_count / (self.cs_hit_count + self.cs_miss_count) if (self.cs_hit_count + self.cs_miss_count) > 0 else 0
            
            content_data = self.cs[interest_name]['data']
            
            # Log aktivitas
            detail_str = (f"CS hit for {interest_name}, To: {from_node}, "
                         f"face_id: {face_id}, CS_hit_ratio: {cs_hit_ratio:.4f}")
            
            self.log_activity('cs_hit', detail_str)
            
            # Kirim data kembali ke node pengirim
            return self.send_data(interest_name, content_data, from_node, face_id)
        
        # CS miss
        self.cs_miss_count += 1
        cs_hit_ratio = self.cs_hit_count / (self.cs_hit_count + self.cs_miss_count) if (self.cs_hit_count + self.cs_miss_count) > 0 else 0
        
        # Cek apakah Interest ini sudah ada di PIT
        if interest_name in self.pit:
            # Tambahkan node pengirim ke daftar yang menunggu
            self.pit[interest_name].append({
                'node_id': from_node,
                'face_id': face_id,
                'arrival_time': time.time()
            })
            
            # Log aktivitas
            detail_str = (f"PIT updated for {interest_name}, From: {from_node}, "
                         f"face_id: {face_id}, CS_hit_ratio: {cs_hit_ratio:.4f}")
            
            self.log_activity('pit_updated', detail_str)
            
            return {'status': 'pit_updated', 'interest_name': interest_name}
        
        # Interest baru, tambahkan ke PIT jika belum penuh
        if len(self.pit) >= self.pit_max_size:
            # PIT penuh, drop Interest
            detail_str = (f"PIT full, dropping {interest_name}, From: {from_node}, "
                         f"face_id: {face_id}")
            
            self.log_activity('pit_full_drop', detail_str)
            
            return {'status': 'pit_full_drop', 'interest_name': interest_name}
        
        # Tambahkan ke PIT
        self.pit[interest_name] = [{
            'node_id': from_node,
            'face_id': face_id,
            'arrival_time': time.time()
        }]
        
        # Cari entri FIB yang cocok
        fib_entry = self.find_matching_fib_entry(interest_name)
        
        if not fib_entry:
            # Tidak ada entri FIB yang cocok, Interest tidak dapat diteruskan
            detail_str = (f"No FIB match for {interest_name}, From: {from_node}, "
                         f"face_id: {face_id}")
            
            self.log_activity('no_fib_match', detail_str)
            
            return {'status': 'no_route', 'interest_name': interest_name}
        
        # Forward Interest ke next hop
        next_hop = fib_entry['next_hop']
        next_face_id = fib_entry['face_id']
        
        # Log aktivitas
        detail_str = (f"Forwarding {interest_name}, From: {from_node}, "
                     f"To: {next_hop}, face_id: {next_face_id}")
        
        self.log_activity('interest_forwarded', detail_str)
        
        # Simulasikan delay jaringan
        if next_hop in self.links:
            face = self.faces.get(next_face_id)
            if face:
                face.transmit_packet(interest_size)
        
        return {
            'status': 'forwarded',
            'interest_name': interest_name,
            'next_hop': next_hop,
            'face_id': next_face_id
        }
    
    def receive_data(self, content_name, content_data, from_node, face_id):
        """Menerima dan memproses Data packet"""
        # Update statistik
        self.packet_count += 1
        content_size = len(content_data)
        self.byte_count += content_size
        
        # Update face
        if face_id in self.faces:
            self.faces[face_id].receive_packet(content_size)
        
        # Perbarui CPU utilization
        self.update_cpu_util()
        
        # Log aktivitas
        detail_str = (f"Data received: {content_name}, From: {from_node}, "
                     f"face_id: {face_id}, Size: {content_size} bytes")
        
        self.log_activity('data_received', detail_str)
        
        # Simpan di Content Store jika ada ruang
        if len(self.cs) < self.cs_max_size:
            self.cs[content_name] = {
                'data': content_data,
                'expiry': time.time() + 300  # Cache selama 5 menit
            }
        elif self.cs:
            # Jika CS penuh, hapus entri tertua
            oldest_content = min(self.cs.items(), key=lambda x: x[1]['expiry'])
            del self.cs[oldest_content[0]]
            
            # Tambahkan konten baru
            self.cs[content_name] = {
                'data': content_data,
                'expiry': time.time() + 300  # Cache selama 5 menit
            }
        
        # Cek PIT untuk Interest yang menunggu
        if content_name in self.pit:
            # Dapatkan daftar node yang menunggu
            waiting_nodes = self.pit[content_name]
            
            # Hapus dari PIT
            del self.pit[content_name]
            
            # Increment counter
            self.pit_satisfaction_count += 1
            
            # Forward Data ke semua node yang menunggu
            forwarded_to = []
            for entry in waiting_nodes:
                node_id = entry['node_id']
                node_face_id = entry['face_id']
                
                # Log aktivitas
                detail_str = (f"Forwarding data: {content_name}, To: {node_id}, "
                             f"face_id: {node_face_id}, Size: {content_size} bytes")
                
                self.log_activity('data_forwarded', detail_str)
                
                # Update face
                if node_face_id in self.faces:
                    self.faces[node_face_id].transmit_packet(content_size)
                
                forwarded_to.append({
                    'node': node_id,
                    'face_id': node_face_id
                })
            
            return {
                'status': 'forwarded',
                'content_name': content_name,
                'nodes': forwarded_to
            }
        
        # Tidak ada entri PIT yang cocok
        detail_str = (f"No PIT match for {content_name}, From: {from_node}, "
                     f"face_id: {face_id}")
        
        self.log_activity('no_pit_match', detail_str)
        
        return {'status': 'no_pit_match', 'content_name': content_name}
    
    def send_data(self, content_name, content_data, to_node, face_id):
        """Mengirim Data packet ke node lain"""
        # Update statistik
        self.packet_count += 1
        content_size = len(content_data)
        self.byte_count += content_size
        
        # Update face
        if face_id in self.faces:
            self.faces[face_id].transmit_packet(content_size)
        
        # Log aktivitas
        detail_str = (f"Sending data: {content_name}, To: {to_node}, "
                     f"face_id: {face_id}, Size: {content_size} bytes")
        
        self.log_activity('data_sent', detail_str)
        
        return {
            'status': 'sent',
            'content_name': content_name,
            'to_node': to_node,
            'face_id': face_id
        }
    
    def cleanup_pit(self):
        """Membersihkan entri PIT yang sudah expired"""
        current_time = time.time()
        expired_entries = []
        
        for interest_name, entries in self.pit.items():
            # Filter entri yang belum expired
            valid_entries = [entry for entry in entries 
                            if current_time - entry['arrival_time'] <= self.pit_entry_timeout]
            
            # Jika ada entri yang expired
            if len(valid_entries) < len(entries):
                expired_count = len(entries) - len(valid_entries)
                self.pit_expiry_count += expired_count
                
                # Log aktivitas
                detail_str = (f"PIT entry expired: {interest_name}, "
                             f"Expired entries: {expired_count}")
                
                self.log_activity('pit_entry_expired', detail_str)
            
            # Jika masih ada entri valid
            if valid_entries:
                self.pit[interest_name] = valid_entries
            else:
                expired_entries.append(interest_name)
        
        # Hapus entri yang sepenuhnya expired
        for interest_name in expired_entries:
            del self.pit[interest_name]
    
    def update_cpu_util(self):
        """Memperbarui CPU utilization berdasarkan aktivitas"""
        current_time = time.time()
        time_diff = current_time - self.last_cpu_update
        
        # Hanya update jika sudah lebih dari 1 detik
        if time_diff >= 1.0:
            # CPU utilization berdasarkan jumlah paket yang diproses
            # dan ukuran PIT dan CS
            packet_factor = min(0.1 * self.packet_count / time_diff, 50)
            pit_factor = min(0.02 * len(self.pit), 30)
            cs_factor = min(0.01 * len(self.cs), 20)
            
            # CPU utilization total (maksimum 100%)
            self.cpu_util = min(packet_factor + pit_factor + cs_factor, 100)
            
            # Memory utilization berdasarkan ukuran PIT dan CS
            self.memory_util = min((len(self.pit) / self.pit_max_size) * 60 + 
                                  (len(self.cs) / self.cs_max_size) * 40, 100)
            
            # Reset counter untuk periode berikutnya
            self.packet_count = 0
            self.last_cpu_update = current_time
    
    def get_nfd_status(self):
        """Mendapatkan status NFD (Named Data Networking Forwarding Daemon)"""
        uptime = time.time() - self.start_time
        cs_hit_ratio = self.cs_hit_count / (self.cs_hit_count + self.cs_miss_count) if (self.cs_hit_count + self.cs_miss_count) > 0 else 0
        pit_satisfaction_ratio = self.pit_satisfaction_count / (self.pit_satisfaction_count + self.pit_expiry_count) if (self.pit_satisfaction_count + self.pit_expiry_count) > 0 else 0
        
        # Dalam implementasi sebenarnya, ini akan memanggil nfd-status
        # dan mengurai hasilnya
        
        return {
            'node_id': self.node_id,
            'uptime': uptime,
            'version': 'NFD 0.7.1',  # Versi NFD yang sebenarnya
            'general': {
                'network_region': self.network_prefix,
                'hostname': f"{self.node_id}.ndn.telkom_university",
                'site': 'Telkom University',
                'start_time': datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')
            },
            'counters': {
                'pit_satisfaction': self.pit_satisfaction_count,
                'pit_expiry': self.pit_expiry_count,
                'cs_hits': self.cs_hit_count,
                'cs_misses': self.cs_miss_count,
                'incoming_packets': sum(face.packets_in for face in self.faces.values()),
                'outgoing_packets': sum(face.packets_out for face in self.faces.values()),
                'incoming_bytes': sum(face.bytes_in for face in self.faces.values()),
                'outgoing_bytes': sum(face.bytes_out for face in self.faces.values())
            },
            'tables': {
                'pit_size': len(self.pit),
                'pit_max_size': self.pit_max_size,
                'cs_size': len(self.cs),
                'cs_max_size': self.cs_max_size,
                'fib_size': sum(len(entries) for entries in self.fib.values())
            },
            'performance': {
                'cpu_utilization': self.cpu_util,
                'memory_utilization': self.memory_util,
                'cs_hit_ratio': cs_hit_ratio,
                'pit_satisfaction_ratio': pit_satisfaction_ratio
            }
        }
    
    def get_pit_status(self):
        """Mendapatkan status PIT"""
        current_time = time.time()
        pit_entries = []
        
        for interest_name, entries in self.pit.items():
            for entry in entries:
                remaining_time = self.pit_entry_timeout - (current_time - entry['arrival_time'])
                if remaining_time > 0:
                    pit_entries.append({
                        'interest_name': interest_name,
                        'from_node': entry['node_id'],
                        'face_id': entry['face_id'],
                        'arrival_time': entry['arrival_time'],
                        'remaining_time': remaining_time
                    })
        
        # Urutkan berdasarkan remaining time (terkecil dulu)
        pit_entries.sort(key=lambda x: x['remaining_time'])
        
        pit_satisfaction_rate = self.pit_satisfaction_count / (self.pit_satisfaction_count + self.pit_expiry_count) if (self.pit_satisfaction_count + self.pit_expiry_count) > 0 else 0
        
        return {
            'pit_size': len(self.pit),
            'pit_max_size': self.pit_max_size,
            'pit_entry_count': sum(len(entries) for entries in self.pit.values()),
            'pit_satisfaction_rate': pit_satisfaction_rate,
            'pit_expiry_count': self.pit_expiry_count,
            'pit_entries': pit_entries
        }
    
    def get_fib_status(self):
        """Mendapatkan status FIB"""
        fib_entries = []
        
        for prefix, entries in self.fib.items():
            for entry in entries:
                fib_entries.append({
                    'prefix': prefix,
                    'nexthop': entry['next_hop'],
                    'face_id': entry['face_id'],
                    'cost': entry['cost']
                })
        
        # Urutkan berdasarkan prefix
        fib_entries.sort(key=lambda x: x['prefix'])
        
        return {
            'fib_size': sum(len(entries) for entries in self.fib.values()),
            'fib_prefix_count': len(self.fib),
            'fib_entries': fib_entries
        }


# ==============================
# SECTION: Kelas Consumer
# ==============================

class NDNConsumer(NDNNode):
    """Consumer node yang meminta konten menggunakan NDN API
    
    Referensi implementasi:
    - PyNDN2: https://github.com/named-data/PyNDN2
    - NDN-CCL: https://github.com/named-data/ndn-ccl
    """
    
    def __init__(self, node_id, network_prefix):
        super().__init__(node_id, 'consumer', network_prefix)
        # Tetapkan interest rate berdasarkan pola node_id
        if 'mhs' in node_id:
            self.interest_rate = 8.0  # 8 Interest per detik untuk mahasiswa (lebih tinggi dari dosen)
        elif 'ds' in node_id:
            self.interest_rate = 5.0  # 5 Interest per detik untuk dosen
        elif 'stf' in node_id or 'stud' in node_id:
            self.interest_rate = 3.0  # 3 Interest per detik untuk staff/student
        elif 'tamu' in node_id or 'putra' in node_id or 'putri' in node_id:
            self.interest_rate = 2.0  # 2 Interest per detik untuk tamu/asrama
        elif 'perp' in node_id:
            self.interest_rate = 4.0  # 4 Interest per detik untuk perpustakaan
        else:
            self.interest_rate = 3.0  # Default
        
        self.interests_sent = 0
        self.data_received = 0
        self.timeouts = 0
        self.rtt_samples = []  # Round Trip Time samples
        self.content_preferences = self.determine_content_preferences(node_id)
        
        # Tambahkan referensi ke consumer app yang sebenarnya
        self.consumer_app = None
        # Tambahkan referensi ke keychain untuk signing
        self.keychain = None

    
    def determine_content_preferences(self, node_id):
        """Menentukan preferensi konten berdasarkan jenis consumer"""
        preferences = {}
        
        # Mahasiswa lebih sering mengakses konten akademik dan perpustakaan
        if 'mhs' in node_id:
            preferences[CONTENT_PREFIXES[0]] = 0.4  # akademik
            preferences[CONTENT_PREFIXES[2]] = 0.3  # perpustakaan
            preferences[CONTENT_PREFIXES[1]] = 0.2  # penelitian
            preferences[CONTENT_PREFIXES[4]] = 0.1  # repository
            preferences[CONTENT_PREFIXES[3]] = 0.0  # strategis
        
        # Dosen lebih sering mengakses konten penelitian dan repository
        elif 'ds' in node_id:
            preferences[CONTENT_PREFIXES[1]] = 0.4  # penelitian
            preferences[CONTENT_PREFIXES[4]] = 0.3  # repository
            preferences[CONTENT_PREFIXES[0]] = 0.2  # akademik
            preferences[CONTENT_PREFIXES[2]] = 0.1  # perpustakaan
            preferences[CONTENT_PREFIXES[3]] = 0.0  # strategis
        
        # Staff lebih sering mengakses konten akademik dan strategis
        elif 'stf' in node_id:
            preferences[CONTENT_PREFIXES[0]] = 0.4  # akademik
            preferences[CONTENT_PREFIXES[3]] = 0.3  # strategis
            preferences[CONTENT_PREFIXES[4]] = 0.2  # repository
            preferences[CONTENT_PREFIXES[1]] = 0.1  # penelitian
            preferences[CONTENT_PREFIXES[2]] = 0.0  # perpustakaan
        
        # Tamu lebih sering mengakses konten perpustakaan dan strategis
        elif 'tamu' in node_id:
            preferences[CONTENT_PREFIXES[2]] = 0.5  # perpustakaan
            preferences[CONTENT_PREFIXES[3]] = 0.3  # strategis
            preferences[CONTENT_PREFIXES[0]] = 0.2  # akademik
            preferences[CONTENT_PREFIXES[1]] = 0.0  # penelitian
            preferences[CONTENT_PREFIXES[4]] = 0.0  # repository
        
        # Perpustakaan lebih sering mengakses konten perpustakaan dan repository
        elif 'perp' in node_id:
            preferences[CONTENT_PREFIXES[2]] = 0.6  # perpustakaan
            preferences[CONTENT_PREFIXES[4]] = 0.4  # repository
            preferences[CONTENT_PREFIXES[0]] = 0.0  # akademik
            preferences[CONTENT_PREFIXES[1]] = 0.0  # penelitian
            preferences[CONTENT_PREFIXES[3]] = 0.0  # strategis
        
        # Student housing lebih sering mengakses konten akademik dan perpustakaan
        elif 'stud' in node_id or 'putra' in node_id or 'putri' in node_id:
            preferences[CONTENT_PREFIXES[0]] = 0.5  # akademik
            preferences[CONTENT_PREFIXES[2]] = 0.3  # perpustakaan
            preferences[CONTENT_PREFIXES[4]] = 0.2  # repository
            preferences[CONTENT_PREFIXES[1]] = 0.0  # penelitian
            preferences[CONTENT_PREFIXES[3]] = 0.0  # strategis
        
        # Default - distribusi seragam
        else:
            for prefix in CONTENT_PREFIXES:
                preferences[prefix] = 1.0 / len(CONTENT_PREFIXES)
        
        return preferences
    
    def select_content(self):
        """Memilih konten berdasarkan preferensi"""
        # Pilih prefix berdasarkan preferensi
        prefix = self.weighted_choice(self.content_preferences)
        
        # Pilih konten spesifik dari katalog
        if prefix in CONTENT_CATALOG:
            content = self.select_from_list(CONTENT_CATALOG[prefix])
            content_name = f"{prefix}/{content['name']}"
            content_size = content['size']
            return content_name, content_size
        else:
            # Fallback jika prefix tidak ada dalam katalog
            return f"{prefix}/default", 1024
    
    def weighted_choice(self, weights_dict):
        """Memilih item berdasarkan bobot"""
        items = list(weights_dict.keys())
        weights = list(weights_dict.values())
        
        # Normalisasi bobot jika perlu
        total = sum(weights)
        if total > 0:
            weights = [w/total for w in weights]
        else:
            # Jika semua bobot 0, gunakan distribusi seragam
            weights = [1.0/len(weights) for _ in weights]
        
        # Akumulasi bobot untuk pemilihan
        cum_weights = []
        cum_sum = 0
        for w in weights:
            cum_sum += w
            cum_weights.append(cum_sum)
        
        # Pilih item berdasarkan bobot
        r = random.random()
        for i, cum_weight in enumerate(cum_weights):
            if r <= cum_weight:
                return items[i]
        
        return items[-1]  # Fallback
    
    def select_from_list(self, items):
        """Memilih item dari daftar"""
        return random.choice(items)
    
    def generate_interest(self):
        """Menghasilkan Interest untuk konten"""
        content_name, _ = self.select_content()
        self.interests_sent += 1
        
        # Log aktivitas
        detail_str = f"Generated Interest: {content_name}, Count: {self.interests_sent}"
        self.log_activity('interest_generated', detail_str)
        
        return content_name
    
    def send_interest(self, router_id, face_id):
        """Mengirim Interest ke router menggunakan NDN API"""
        interest_name = self.generate_interest()
        interest_size = len(interest_name) + 40  # Estimasi ukuran paket
        
        # Update face
        if face_id in self.faces:
            self.faces[face_id].transmit_packet(interest_size)
        
        # Log aktivitas
        detail_str = f"Sending Interest: {interest_name}, To: {router_id}, Face: {face_id}"
        self.log_activity('interest_sent', detail_str)
        
        # Simpan waktu pengiriman untuk menghitung RTT
        send_time = time.time()
        
        # Dalam implementasi sebenarnya, ini akan menggunakan PyNDN untuk mengirim Interest
        # Misalnya:
        # interest = Interest(Name(interest_name))
        # interest.setInterestLifetimeMilliseconds(4000)  # 4 detik
        # interest.setMustBeFresh(True)
        # self.face.expressInterest(interest, self.on_data, self.on_timeout)
        
        return {
            'interest_name': interest_name,
            'from_node': self.node_id,
            'to_node': router_id,
            'face_id': face_id,
            'send_time': send_time
        }
    
    def receive_data(self, content_name, content_data, from_node, face_id, send_time):
        """Menerima Data packet dari router"""
        # Update statistik
        self.data_received += 1
        content_size = len(content_data)
        self.byte_count += content_size
        
        # Update face
        if face_id in self.faces:
            self.faces[face_id].receive_packet(content_size)
        
        # Hitung RTT
        rtt = time.time() - send_time
        self.rtt_samples.append(rtt)
        
        # Log aktivitas
        detail_str = (f"Data received: {content_name}, From: {from_node}, "
                     f"Face: {face_id}, Size: {content_size} bytes, RTT: {rtt:.6f}s")
        
        self.log_activity('data_received', detail_str)
        
        # Dalam implementasi sebenarnya, ini akan dipanggil oleh callback pada expressInterest
        
        return {
            'status': 'received',
            'content_name': content_name,
            'from_node': from_node,
            'rtt': rtt
        }
    
    def handle_timeout(self, interest_name):
        """Menangani timeout untuk Interest"""
        self.timeouts += 1
        
        # Log aktivitas
        detail_str = f"Interest timeout: {interest_name}, Timeout count: {self.timeouts}"
        self.log_activity('interest_timeout', detail_str)
        
        # Dalam implementasi sebenarnya, ini akan dipanggil oleh callback pada expressInterest
        
        return {
            'status': 'timeout',
            'interest_name': interest_name
        }
    
    def get_consumer_stats(self):
        """Mendapatkan statistik consumer"""
        avg_rtt = sum(self.rtt_samples) / len(self.rtt_samples) if self.rtt_samples else 0
        min_rtt = min(self.rtt_samples) if self.rtt_samples else 0
        max_rtt = max(self.rtt_samples) if self.rtt_samples else 0
        
        return {
            'node_id': self.node_id,
            'interests_sent': self.interests_sent,
            'data_received': self.data_received,
            'timeouts': self.timeouts,
            'satisfaction_rate': self.data_received / self.interests_sent if self.interests_sent > 0 else 0,
            'avg_rtt': avg_rtt,
            'min_rtt': min_rtt,
            'max_rtt': max_rtt,
            'interest_rate': self.interest_rate
        }


# ==============================
# SECTION: Kelas Producer
# ==============================

class NDNProducer(NDNNode):
    """Producer node yang menyediakan konten menggunakan NDN API
    
    Referensi implementasi:
    - PyNDN2: https://github.com/named-data/PyNDN2
    - NFD: https://github.com/named-data/NFD
    """
    
    def __init__(self, node_id, network_prefix):
        super().__init__(node_id, 'producer', network_prefix)
        self.content_served = 0
        self.content_prefix = self.determine_content_prefix(node_id)
        self.content_catalog = self.generate_content_catalog()
        
        # Tambahkan referensi ke producer app yang sebenarnya
        self.producer_app = None
        # Tambahkan referensi ke keychain untuk signing
        self.keychain = None
    
    def determine_content_prefix(self, node_id):
        """Menentukan prefix konten berdasarkan jenis producer"""
        if 'akad' in node_id or 'igr' in node_id:
            return CONTENT_PREFIXES[0]  # akademik
        elif 'pen' in node_id or 'web' in node_id:
            return CONTENT_PREFIXES[1]  # penelitian
        elif 'perp' in node_id or 'lib' in node_id:
            return CONTENT_PREFIXES[2]  # perpustakaan
        elif 'str' in node_id:
            return CONTENT_PREFIXES[3]  # strategis
        elif 'repo' in node_id:
            return CONTENT_PREFIXES[4]  # repository
        else:
            return CONTENT_PREFIXES[0]  # default ke akademik
    
    def generate_content_catalog(self):
        """Menghasilkan katalog konten untuk producer ini"""
        if self.content_prefix in CONTENT_CATALOG:
            return CONTENT_CATALOG[self.content_prefix]
        else:
            # Fallback jika prefix tidak ada dalam katalog global
            return [
                {"name": "default_content_1", "size": 2048},
                {"name": "default_content_2", "size": 3072},
                {"name": "default_content_3", "size": 4096}
            ]
    
    def receive_interest(self, interest_name, from_node, face_id):
        """Menerima dan memproses Interest menggunakan NDN API"""
        # Update statistik
        self.packet_count += 1
        interest_size = len(interest_name) + 40  # Estimasi ukuran paket
        self.byte_count += interest_size
        
        # Update face
        if face_id in self.faces:
            self.faces[face_id].receive_packet(interest_size)
        
        # Log aktivitas
        detail_str = f"Interest received: {interest_name}, From: {from_node}, Face: {face_id}"
        self.log_activity('interest_received', detail_str)
        
        # Dalam implementasi sebenarnya, ini akan dipanggil oleh callback pada setInterestFilter
        
        # Cek apakah Interest cocok dengan prefix konten yang disediakan
        if not interest_name.startswith(self.content_prefix):
            # Interest tidak cocok dengan konten yang disediakan
            detail_str = (f"Interest prefix mismatch: {interest_name}, "
                         f"Producer prefix: {self.content_prefix}")
            
            self.log_activity('interest_prefix_mismatch', detail_str)
            
            return {
                'status': 'prefix_mismatch',
                'interest_name': interest_name
            }
        
        # Cari konten yang diminta
        content_name = interest_name.split('/')[-1] if '/' in interest_name else interest_name
        content_data = None
        content_size = 0
        
        for content in self.content_catalog:
            if content['name'] == content_name:
                # Buat data konten dengan ukuran yang sesuai
                content_data = f"Content for {interest_name}" + "X" * content['size']
                content_size = content['size']
                break
        
        # Jika konten tidak ditemukan, buat default
        if not content_data:
            content_data = f"Default content for {interest_name}" + "X" * 1024
            content_size = 1024
        
        # Update statistik
        self.content_served += 1
        
        # Log aktivitas
        detail_str = (f"Serving content: {interest_name}, To: {from_node}, "
                     f"Face: {face_id}, Size: {content_size} bytes")
        
        self.log_activity('content_served', detail_str)
        
        # Dalam implementasi sebenarnya, ini akan membuat Data packet dengan PyNDN
        # Misalnya:
        # data = Data(Name(interest_name))
        # data.setContent(content_data)
        # self.keychain.sign(data)
        # self.face.putData(data)
        
        # Kirim Data packet kembali
        return self.send_data(interest_name, content_data, from_node, face_id)
    
    def send_data(self, content_name, content_data, to_node, face_id):
        """Mengirim Data packet ke node lain"""
        # Update statistik
        self.packet_count += 1
        content_size = len(content_data)
        self.byte_count += content_size
        
        # Update face
        if face_id in self.faces:
            self.faces[face_id].transmit_packet(content_size)
        
        # Log aktivitas
        detail_str = (f"Sending data: {content_name}, To: {to_node}, "
                     f"Face: {face_id}, Size: {content_size} bytes")
        
        self.log_activity('data_sent', detail_str)
        
        return {
            'status': 'sent',
            'content_name': content_name,
            'content_data': content_data,
            'to_node': to_node,
            'face_id': face_id,
            'size': content_size
        }
    
    def get_producer_stats(self):
        """Mendapatkan statistik producer"""
        return {
            'node_id': self.node_id,
            'content_prefix': self.content_prefix,
            'content_served': self.content_served,
            'catalog_size': len(self.content_catalog),
            'total_bytes_sent': self.byte_count
        }
    
    def register_prefix(self):
        """Mendaftarkan prefix di NFD"""
        # Dalam implementasi sebenarnya, ini akan menggunakan PyNDN untuk mendaftarkan prefix
        # Misalnya:
        # self.face.registerPrefix(Name(self.content_prefix), self.on_interest, self.on_register_failed)
        pass


# ==============================
# SECTION: Kelas Attacker
# ==============================

class NDNAttacker(NDNNode):
    """Attacker node yang melakukan serangan pada jaringan NDN
    
    Referensi implementasi serangan:
    - Interest Flooding: Gasti et al. [4] - "DoS and DDoS in Named Data Networking"
      Implementasi berdasarkan paper ini yang menjelaskan bagaimana penyerang dapat
      menghabiskan resource PIT router dengan mengirimkan banyak Interest untuk
      konten yang tidak ada.
      
    - Cache Poisoning: Ghali et al. "Network-Layer Trust in Named-Data Networking"
      Paper ini menjelaskan bagaimana penyerang dapat meracuni cache dengan
      mengirimkan data palsu yang akan disimpan di Content Store router.
    """
    
    def __init__(self, node_id, network_prefix):
        super().__init__(node_id, 'attacker', network_prefix)
        self.attack_type = self.determine_attack_type(node_id)
        self.attack_rate = self.determine_attack_rate(node_id)
        self.attacks_launched = 0
        self.attack_targets = []
        self.attack_prefixes = self.determine_attack_prefixes()
        
        # Tambahkan referensi ke attacker app yang sebenarnya
        self.attacker_app = None
    
    def determine_attack_type(self, node_id):
        """Menentukan jenis serangan berdasarkan node_id"""
        if 'ext' in node_id:
            # External attacker - interest flooding
            return 'interest_flooding'
        elif 'int' in node_id:
            # Internal attacker - cache poisoning
            return 'cache_poisoning'
        else:
            # Default ke interest flooding
            print(f"Warning: Unknown attacker type for {node_id}, defaulting to interest_flooding")
            return 'interest_flooding'

    
    def determine_attack_rate(self, node_id):
        """Menentukan rate serangan berdasarkan node_id"""
        if 'ext1' in node_id:
            return 20.0  # 20 serangan per detik (ditingkatkan dari 10)
        elif 'ext2' in node_id:
            return 25.0  # 25 serangan per detik (ditingkatkan dari 15)
        elif 'int' in node_id:
            return 15.0  # 15 serangan per detik (ditingkatkan dari 5)
        else:
            return 18.0  # default (ditingkatkan dari 8)
    
    def determine_attack_prefixes(self):
        """Menentukan prefix yang akan diserang"""
        # Untuk interest flooding, serang semua prefix
        if self.attack_type == 'interest_flooding':
            return CONTENT_PREFIXES
     
        # Untuk cache poisoning, fokus pada prefix akademik dan perpustakaan
        else:
            return [CONTENT_PREFIXES[0], CONTENT_PREFIXES[2]]
    
    def generate_attack_interest(self):
        """Menghasilkan Interest untuk serangan"""
        prefix = random.choice(self.attack_prefixes)
        
        if self.attack_type == 'interest_flooding':
            # Buat Interest dengan nama acak yang tidak ada
            random_suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10))
            interest_name = f"{prefix}/nonexistent/{random_suffix}"
        else:
            # Untuk cache poisoning, gunakan nama yang valid
            if prefix in CONTENT_CATALOG:
                content = random.choice(CONTENT_CATALOG[prefix])
                interest_name = f"{prefix}/{content['name']}"
            else:
                interest_name = f"{prefix}/default"
        
        self.attacks_launched += 1
        
        # Log aktivitas
        detail_str = (f"Generated attack Interest: {interest_name}, "
                     f"Type: {self.attack_type}, Count: {self.attacks_launched}")
        
        self.log_activity('attack_generated', detail_str, is_attack=True)
        
        return interest_name
    
    def launch_attack(self, router_id, face_id):
        """Meluncurkan serangan ke router"""
        if self.attack_type == 'interest_flooding':
            # Interest Flooding Attack
            interest_name = self.generate_attack_interest()
            interest_size = len(interest_name) + 40  # Estimasi ukuran paket
            
            # Update face
            if face_id in self.faces:
                self.faces[face_id].transmit_packet(interest_size)
            
            # Log aktivitas
            detail_str = (f"Launching IFA: {interest_name}, To: {router_id}, "
                        f"Face: {face_id}")
            self.log_activity('attack_launched', detail_str, is_attack=True)
            
            # Tambahkan target ke daftar
            if router_id not in self.attack_targets:
                self.attack_targets.append(router_id)
            
            return {
                'interest_name': interest_name,
                'from_node': self.node_id,
                'to_node': router_id,
                'face_id': face_id,
                'attack_type': self.attack_type,
                'is_attack': True
            }
        
        elif self.attack_type == 'cache_poisoning':
            # Cache Poisoning Attack - pertama kirim Interest normal
            interest_name = self.generate_attack_interest()
            interest_size = len(interest_name) + 40
            
            # Update face
            if face_id in self.faces:
                self.faces[face_id].transmit_packet(interest_size)
            
            # Log aktivitas
            detail_str = (f"Launching CPA phase 1: {interest_name}, To: {router_id}, "
                        f"Face: {face_id}")
            self.log_activity('attack_launched', detail_str, is_attack=True)
            
            # Tambahkan target ke daftar
            if router_id not in self.attack_targets:
                self.attack_targets.append(router_id)
            
            return {
                'interest_name': interest_name,
                'from_node': self.node_id,
                'to_node': router_id,
                'face_id': face_id,
                'attack_type': self.attack_type,
                'is_attack': True,
                'is_cpa_phase1': True  # Tandai ini sebagai fase 1 dari CPA
            }

    
    def receive_data(self, content_name, content_data, from_node, face_id):
        """Menerima Data packet (untuk serangan cache poisoning)"""
        # Update statistik
        self.packet_count += 1
        content_size = len(content_data)
        self.byte_count += content_size
        
        # Update face
        if face_id in self.faces:
            self.faces[face_id].receive_packet(content_size)
        
        # Log aktivitas
        detail_str = (f"Data received for attack: {content_name}, From: {from_node}, "
                     f"Face: {face_id}, Size: {content_size} bytes")
        
        self.log_activity('attack_data_received', detail_str, is_attack=True)
        
        # Jika cache poisoning, kirim data palsu kembali
        if self.attack_type == 'cache_poisoning':
            # Buat data palsu
            fake_data = f"FAKE DATA for {content_name}" + "X" * content_size
            
            # Log aktivitas
            detail_str = (f"Sending poisoned data: {content_name}, To: {from_node}, "
                         f"Face: {face_id}, Size: {content_size} bytes")
            
            self.log_activity('cache_poisoning', detail_str, is_attack=True)
            
            # Dalam implementasi sebenarnya, ini akan membuat Data packet palsu dengan PyNDN
            
            return {
                'status': 'poisoned',
                'content_name': content_name,
                'content_data': fake_data,
                'to_node': from_node,
                'face_id': face_id,
                'is_attack': True
            }
        
        return {
            'status': 'received',
            'content_name': content_name,
            'from_node': from_node
        }
    
    def get_attacker_stats(self):
        """Mendapatkan statistik attacker"""
        return {
            'node_id': self.node_id,
            'attack_type': self.attack_type,
            'attacks_launched': self.attacks_launched,
            'attack_rate': self.attack_rate,
            'attack_targets': self.attack_targets,
            'attack_prefixes': self.attack_prefixes
        }


# ==============================
# SECTION: Kelas Simulasi
# ==============================

class NDNSimulation:
    """Simulasi jaringan NDN menggunakan MiniNDN
    
    Referensi implementasi:
    - MiniNDN: https://github.com/named-data/mini-ndn
    - NFD: https://github.com/named-data/NFD
    - NLSR: https://github.com/named-data/NLSR
    """
    
    def __init__(self, topology_file):
        self.topology_file = topology_file
        self.nodes = {}  # {node_id: NDNNode}
        self.links = []  # [(node1_id, node2_id, delay, bandwidth)]
        self.running = False
        self.start_time = None
        self.end_time = None
        self.dataset = []
        self.pcap_process = None
        
        # Tambahkan referensi ke objek MiniNDN
        self.minindn = None
        # Tambahkan referensi ke AppManager
        self.app_manager = None
    
    def parse_topology(self):
        """Mengurai file topologi untuk membuat jaringan"""
        print(SECTION_HEADER("PARSING TOPOLOGY"))
        print(f"Parsing topology file: {self.topology_file}")
        
        try:
            with open(self.topology_file, 'r') as f:
                content = f.read()
            
            # Pisahkan bagian nodes dan links
            sections = content.split('[links]')
            if len(sections) != 2:
                print("Format file topologi tidak valid")
                return False
            
            nodes_section = sections[0].strip()
            links_section = sections[1].strip()
            
            # Parse nodes
            in_nodes_section = False
            for line in nodes_section.split('\n'):
                line = line.strip()
                
                if line.startswith('[nodes]'):
                    in_nodes_section = True
                    continue
                
                if not in_nodes_section or not line or line.startswith('#'):
                    continue
                
                # Format: node_id: _ network=/prefix router=/router_path/
                parts = line.split(':')
                if len(parts) != 2:
                    continue
                
                node_id = parts[0].strip()
                node_params = parts[1].strip()
                
                # Extract network prefix
                network_prefix = None
                if 'network=' in node_params:
                    network_start = node_params.find('network=') + len('network=')
                    network_end = node_params.find(' ', network_start)
                    if network_end == -1:
                        network_end = len(node_params)
                    network_prefix = node_params[network_start:network_end]
                
                if not network_prefix:
                    network_prefix = '/ndn_telkom_university'
                
                # Buat node berdasarkan prefiks nama
                if node_id.startswith('r_') or node_id.startswith('rl_') or node_id.startswith('rk_') or node_id.startswith('g_'):
                    self.nodes[node_id] = NDNRouter(node_id, network_prefix)
                elif node_id.startswith('c_'):
                    self.nodes[node_id] = NDNConsumer(node_id, network_prefix)
                elif node_id.startswith('p_'):
                    self.nodes[node_id] = NDNProducer(node_id, network_prefix)
                elif node_id.startswith('a_'):
                    self.nodes[node_id] = NDNAttacker(node_id, network_prefix)
                else:
                    # Default ke router
                    self.nodes[node_id] = NDNRouter(node_id, network_prefix)
            
            # Parse links
            for line in links_section.split('\n'):
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                # Format: node1:node2 delay=Xms bandwidth=YMbps
                parts = line.split(' ')
                if len(parts) < 3:
                    continue
                
                nodes_part = parts[0]
                node_ids = nodes_part.split(':')
                if len(node_ids) != 2:
                    continue
                
                node1_id = node_ids[0].strip()
                node2_id = node_ids[1].strip()
                
                # Extract delay and bandwidth
                delay = '5ms'  # default
                bandwidth = '10'  # default in Mbps
                
                for param in parts[1:]:
                    if 'delay=' in param:
                        delay = param.split('=')[1]
                    elif 'bandwidth=' in param:
                        bandwidth = param.split('=')[1]
                
                # Add link to list
                self.links.append((node1_id, node2_id, delay, bandwidth))
            
            # Establish links between nodes
            for node1_id, node2_id, delay, bandwidth in self.links:
                if node1_id in self.nodes and node2_id in self.nodes:
                    node1 = self.nodes[node1_id]
                    node2 = self.nodes[node2_id]
                    
                    # Create bidirectional links
                    face1_id = node1.add_link(node2_id, delay, bandwidth)
                    face2_id = node2.add_link(node1_id, delay, bandwidth)
                    
                    print(f"Established link: {node1_id}:{node2_id} with delay={delay}, bandwidth={bandwidth}")
                else:
                    print(f"Warning: Cannot establish link {node1_id}:{node2_id}, one or both nodes missing")

            # Configure FIB entries for all routers
            self.configure_routing()
            
            print(f"\nTopology parsed successfully: {len(self.nodes)} nodes, {len(self.links)} links")
            
            # Tampilkan ringkasan node berdasarkan jenis
            router_count = sum(1 for node in self.nodes.values() if isinstance(node, NDNRouter))
            consumer_count = sum(1 for node in self.nodes.values() if isinstance(node, NDNConsumer))
            producer_count = sum(1 for node in self.nodes.values() if isinstance(node, NDNProducer))
            attacker_count = sum(1 for node in self.nodes.values() if isinstance(node, NDNAttacker))
            
            print("\nNode Summary:")
            print(f"  Routers   : {router_count}")
            print(f"  Consumers : {consumer_count}")
            print(f"  Producers : {producer_count}")
            print(f"  Attackers : {attacker_count}")
            
            return True
            
        except Exception as e:
            print(f"Error parsing topology: {e}")
            return False
    
    def configure_routing(self):
        """Mengkonfigurasi routing (FIB) untuk semua router"""
        print(SECTION_HEADER("CONFIGURING ROUTING"))
        
        # Identifikasi semua producer dan prefix mereka
        producers = {}  # {prefix: [producer_id, ...]}
        
        for node_id, node in self.nodes.items():
            if isinstance(node, NDNProducer):
                prefix = node.content_prefix
                if prefix not in producers:
                    producers[prefix] = []
                producers[prefix].append(node_id)
        
        # Untuk setiap prefix, tentukan rute dari setiap router ke producer
        for prefix, producer_ids in producers.items():
            for producer_id in producer_ids:
                # Gunakan BFS untuk menemukan rute terpendek dari setiap router ke producer
                routes = self.find_routes_to_node(producer_id)
                
                # Konfigurasi FIB untuk setiap router
                for router_id, route in routes.items():
                    if router_id != producer_id and isinstance(self.nodes[router_id], NDNRouter):
                        router = self.nodes[router_id]
                        next_hop = route['next_hop']
                        face_id = router.links[next_hop]['face_id']
                        cost = route['cost']
                        
                        router.update_fib(prefix, next_hop, face_id, cost)
        
        print("\nRouting configured for all routers")
        print(f"Total prefixes registered: {len(producers)}")
        
        # Dalam implementasi sebenarnya, NLSR akan menangani routing
        # Kita akan mengkonfigurasi NLSR untuk setiap router
        # Tetapi kita tetap mempertahankan konfigurasi manual untuk kompatibilitas
    
    def find_routes_to_node(self, target_node_id):
        """Menemukan rute terpendek dari semua node ke target node menggunakan BFS"""
        routes = {}  # {node_id: {'next_hop': next_hop_id, 'cost': cost}}
        queue = deque([(target_node_id, None, 0)])  # (node_id, prev_node, cost)
        visited = set([target_node_id])
        
        while queue:
            node_id, prev_node, cost = queue.popleft()
            
            if prev_node is not None:
                # Simpan rute untuk node ini
                routes[node_id] = {'next_hop': prev_node, 'cost': cost}
            
            # Tambahkan tetangga yang belum dikunjungi ke queue
            for neighbor_id in self.nodes[node_id].links:
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, node_id, cost + 1))
        
        return routes
    
    def start_pcap_capture(self):
        """Memulai capture paket dengan tcpdump/Wireshark"""
        print(SECTION_HEADER("STARTING PACKET CAPTURE"))
        
        try:
            # Buat direktori output jika belum ada
            os.makedirs(os.path.join(OUTPUT_DIR, "raw_data"), exist_ok=True)
            
            # Path untuk file pcap
            pcap_path = os.path.join(OUTPUT_DIR, "raw_data", PCAP_FILE)
            
            # Buat socket untuk simulasi capture
            self.capture_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.capture_socket.bind(('127.0.0.1', 0))
            self.capture_port = self.capture_socket.getsockname()[1]
            
            # Mulai tcpdump untuk capture paket
            cmd = [
                'tcpdump', '-i', 'lo', 
                '-w', pcap_path,
                f'port {self.capture_port}',
                '-n'
            ]
            
            self.pcap_process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            print(f"Started packet capture on port {self.capture_port}")
            print(f"Saving capture to: {pcap_path}")
            
            # Tunggu sebentar untuk memastikan tcpdump sudah berjalan
            time.sleep(1)
            
            return True
        except Exception as e:
            print(f"Failed to start packet capture: {e}")
            return False
    
    def stop_pcap_capture(self):
        """Menghentikan capture paket"""
        if self.pcap_process:
            self.pcap_process.send_signal(signal.SIGTERM)
            self.pcap_process.wait()
            print("Packet capture stopped")
        
        if hasattr(self, 'capture_socket'):
            self.capture_socket.close()
    
    def send_to_pcap(self, packet_type, from_node, to_node, packet_name, packet_size):
        """Mengirim paket ke tcpdump untuk capture"""
        if not hasattr(self, 'capture_socket'):
            return
        
        try:
            # Format paket untuk capture
            timestamp = time.time()
            packet_data = f"{timestamp},{packet_type},{from_node},{to_node},{packet_name},{packet_size}"
            
            # Kirim ke localhost untuk capture oleh tcpdump
            self.capture_socket.sendto(packet_data.encode(), ('127.0.0.1', self.capture_port))
        except Exception as e:
            print(f"Error sending packet to capture: {e}")
    
    def setup_minindn(self):
        """Menyiapkan MiniNDN untuk simulasi"""
        if not MININDN_AVAILABLE:
            print("MiniNDN tidak tersedia, running in standalone mode")
            return False
        
        try:
            # Siapkan logging
            setLogLevel('info')
            
            # Bersihkan MiniNDN dari simulasi sebelumnya
            Minindn.cleanUp()
            # Verifikasi dependensi
            Minindn.verifyDependencies()
            
            print(f"Using topology file {self.topology_file}")
            
            # Inisialisasi MiniNDN dengan topologi yang sudah diparse
            self.minindn = Minindn(topoFile=self.topology_file)
            
            # Mulai MiniNDN
            self.minindn.start()
            
            # Penting: self.net adalah self.minindn.net, bukan self.minindn
            self.net = self.minindn.net
            
            # Mulai NFD di semua node
            print('Starting NFD on nodes')
            nfds = AppManager(self.minindn, self.net.hosts, Nfd)
            
            # Mulai NLSR di semua router
            print('Starting NLSR on nodes')
            nlsrs = AppManager(self.minindn, self.net.hosts, Nlsr)
            
            # Hubungkan node MiniNDN dengan node simulasi
            for node_id, node in self.nodes.items():
                try:
                    mininet_node = self.net.getNodeByName(node_id)
                    if mininet_node:
                        node.mininet_node = mininet_node
                        if node.node_type == 'router':
                            if hasattr(nfds, 'processes') and node_id in nfds.processes:
                                node.nfd_process = nfds.processes[node_id]
                            if hasattr(nlsrs, 'processes') and node_id in nlsrs.processes:
                                node.nlsr_process = nlsrs.processes[node_id]
                except Exception as e:
                    print(f"Warning: Could not connect node {node_id} to MiniNDN: {e}")
            
            print("MiniNDN setup completed successfully")
            return True
        except Exception as e:
            print(f"Error setting up MiniNDN: {e}")
            import traceback
            traceback.print_exc()  # Tampilkan stack trace lengkap
            return False

    def run(self, duration=SIMULATION_DURATION, start_cli=False):
        """Menjalankan simulasi untuk durasi tertentu"""
        if not self.nodes:
            print("No nodes in topology, cannot run simulation")
            return False
        
        # Buat direktori output jika belum ada
        for subdir in OUTPUT_STRUCTURE.keys():
            os.makedirs(os.path.join(OUTPUT_DIR, subdir), exist_ok=True)
        
        # Setup MiniNDN
        if not self.setup_minindn():
            print("Failed to setup MiniNDN, running in standalone mode")
            return False
        
        # Mulai capture paket
        self.start_pcap_capture()
        
        self.running = True
        self.start_time = time.time()
        self.end_time = self.start_time + duration
        
        print(SECTION_HEADER("RUNNING SIMULATION"))
        print(f"Starting simulation for {duration} seconds")
        
        # Buat thread untuk simulasi
        simulation_thread = threading.Thread(target=self.simulation_loop)
        simulation_thread.start()
        
        try:
            # Tunggu hingga simulasi selesai
            progress_chars = ['|', '/', '-', '\\']
            progress_idx = 0
            
            while time.time() < self.end_time and self.running:
                elapsed = time.time() - self.start_time
                remaining = self.end_time - time.time()
                progress_char = progress_chars[progress_idx]
                progress_idx = (progress_idx + 1) % len(progress_chars)
                
                # Hitung persentase kemajuan
                progress_pct = min(100, (elapsed / duration) * 100)
                
                # Buat progress bar
                bar_width = 40
                bar_filled = int(bar_width * progress_pct / 100)
                bar = '█' * bar_filled + '░' * (bar_width - bar_filled)
                
                print(f"\r{progress_char} Simulation progress: [{bar}] {progress_pct:.1f}% | Elapsed: {elapsed:.1f}s | Remaining: {remaining:.1f}s", end='')
                
                time.sleep(0.2)
            
            print("\n\nSimulation completed")
            self.running = False
            
            # Tunggu thread simulasi selesai
            simulation_thread.join()
            
            # Kumpulkan log NFD
            self.collect_nfd_logs()
            
            # Simpan dataset
            self.save_dataset()
            
            # Tanyakan pengguna apakah ingin memulai CLI atau menjalankan mitigasi
            if start_cli:
                self.start_minindn_cli()
            else:
                print(SECTION_HEADER("POST-SIMULATION OPTIONS"))
                print("Pilih opsi setelah simulasi:")
                print("1. Jalankan Mitigasi")
                print("2. Mulai CLI MiniNDN")
                print("3. Keluar")
                
                choice = input("\nPilihan Anda [1-3]: ")
                
                if choice == '1':
                    self.run_mitigation()
                elif choice == '2':
                    self.start_minindn_cli()
                # Opsi 3 (keluar) tidak perlu dihandle khusus
            
            # Hentikan capture paket
            self.stop_pcap_capture()
            
            # Hentikan MiniNDN jika CLI tidak dijalankan atau setelah CLI selesai
            if hasattr(self, 'net') and self.net:
                self.net.stop()
            
            return True
        
        except KeyboardInterrupt:
            print("\n\nSimulation interrupted by user")
            self.running = False
            simulation_thread.join()
            
            # Tanyakan apakah pengguna ingin memulai CLI atau menjalankan mitigasi
            print(SECTION_HEADER("POST-SIMULATION OPTIONS"))
            print("Pilih opsi setelah simulasi:")
            print("1. Jalankan Mitigasi")
            print("2. Mulai CLI MiniNDN")
            print("3. Keluar")
            
            choice = input("\nPilihan Anda [1-3]: ")
            
            if choice == '1':
                self.run_mitigation()
            elif choice == '2':
                self.start_minindn_cli()
            # Opsi 3 (keluar) tidak perlu dihandle khusus
            
            self.stop_pcap_capture()
            
            # Hentikan MiniNDN
            if hasattr(self, 'net') and self.net:
                self.net.stop()
            
            return False

    def run_mitigation(self):
        """Menjalankan script mitigasi dengan dataset yang dihasilkan"""
        print(SECTION_HEADER("RUNNING MITIGATION"))
        
        # Path ke dataset yang dihasilkan
        dataset_path = os.path.join(OUTPUT_DIR, "dataset", DATASET_FILE)
        
        if not os.path.exists(dataset_path):
            print(f"Error: Dataset file tidak ditemukan di {dataset_path}")
            return False
        
        try:
            # Perintah untuk menjalankan script mitigasi
            mitigation_script = "mitigation.py"
            cmd = ["sudo", "python3", mitigation_script, "--dataset", dataset_path]
            
            print(f"Menjalankan: {' '.join(cmd)}")
            print("Mohon tunggu...")
            
            # Jalankan script mitigasi
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Tampilkan output secara real-time
            for line in process.stdout:
                print(line, end='')
            
            # Tunggu proses selesai
            process.wait()
            
            # Cek apakah proses berhasil
            if process.returncode == 0:
                print("\nMitigasi berhasil dijalankan")
                return True
            else:
                # Tampilkan error jika ada
                error = process.stderr.read()
                print(f"\nError menjalankan mitigasi: {error}")
                return False
                
        except Exception as e:
            print(f"Error menjalankan mitigasi: {e}")
            import traceback
            traceback.print_exc()
            return False


    
    def simulation_loop(self):
        """Loop utama simulasi"""
        # Inisialisasi waktu untuk setiap node
        next_consumer_time = {}
        next_attacker_time = {}
        next_cleanup_time = time.time() + 1.0  # Cleanup PIT setiap 1 detik
        
        for node_id, node in self.nodes.items():
            if isinstance(node, NDNConsumer):
                # Mulai mengirim Interest dengan jitter untuk menghindari sinkronisasi
                next_consumer_time[node_id] = time.time() + random.uniform(0, 1.0 / node.interest_rate)
            
            if isinstance(node, NDNAttacker):
                # Mulai serangan dengan jitter
                next_attacker_time[node_id] = time.time() + random.uniform(0, 1.0 / node.attack_rate)
        
        # Loop simulasi
        while self.running and time.time() < self.end_time:
            current_time = time.time()
            
            # Proses Interest dari consumer
            for node_id, next_time in list(next_consumer_time.items()):
                if current_time >= next_time:
                    consumer = self.nodes[node_id]
                    
                    # Pilih router tujuan (gunakan router yang terhubung langsung)
                    connected_routers = [
                        neighbor_id for neighbor_id in consumer.links
                        if isinstance(self.nodes[neighbor_id], NDNRouter)
                    ]
                    
                    if connected_routers:
                        router_id = connected_routers[0]
                        face_id = consumer.links[router_id]['face_id']
                        
                        # Kirim Interest
                        interest = consumer.send_interest(router_id, face_id)
                        
                        # Proses Interest di router
                        router = self.nodes[router_id]
                        result = router.receive_interest(
                            interest['interest_name'],
                            consumer.node_id,
                            router.links[consumer.node_id]['face_id']
                        )
                        
                        # Tambahkan ke dataset
                        self.add_to_dataset(
                            'interest',
                            consumer.node_id,
                            router_id,
                            interest['interest_name'],
                            len(interest['interest_name']) + 40,
                            False
                        )
                        
                        # Kirim ke pcap
                        self.send_to_pcap(
                            'interest',
                            consumer.node_id,
                            router_id,
                            interest['interest_name'],
                            len(interest['interest_name']) + 40
                        )
                        
                        # Proses forwarding Interest jika perlu
                        self.process_interest_forwarding(result, interest, router)
                        
                        # Simulasi timeout untuk Interest yang tidak terjawab
                        # (dalam implementasi nyata akan ditangani oleh consumer)
                        threading.Timer(
                            4.0,  # timeout setelah 4 detik
                            self.handle_interest_timeout,
                            args=[interest, consumer]
                        ).start()
                    
                    # Jadwalkan Interest berikutnya
                    next_consumer_time[node_id] = current_time + (1.0 / consumer.interest_rate)
            
            # Proses serangan dari attacker
            for node_id, next_time in list(next_attacker_time.items()):
                if current_time >= next_time:
                    attacker = self.nodes[node_id]
                    
                    # Pilih router tujuan (gunakan router yang terhubung langsung)
                    connected_routers = [
                        neighbor_id for neighbor_id in attacker.links
                        if isinstance(self.nodes[neighbor_id], NDNRouter)
                    ]
                    
                    if connected_routers:
                        router_id = connected_routers[0]
                        face_id = attacker.links[router_id]['face_id']
                        
                        # Luncurkan serangan
                        attack = attacker.launch_attack(router_id, face_id)
                        
                        # Proses serangan berdasarkan jenisnya
                        if attacker.attack_type == 'interest_flooding':
                            # Interest Flooding Attack - proses normal
                            router = self.nodes[router_id]
                            result = router.receive_interest(
                                attack['interest_name'],
                                attacker.node_id,
                                router.links[attacker.node_id]['face_id'],
                                is_attack=True
                            )
                            
                            # Tambahkan ke dataset
                            self.add_to_dataset(
                                'attack',
                                attacker.node_id,
                                router_id,
                                attack['interest_name'],
                                len(attack['interest_name']) + 40,
                                True
                            )
                            
                            # Kirim ke pcap
                            self.send_to_pcap(
                                'attack',
                                attacker.node_id,
                                router_id,
                                attack['interest_name'],
                                len(attack['interest_name']) + 40
                            )
                            
                            # Proses forwarding Interest jika perlu
                            self.process_interest_forwarding(result, attack, router)
                        
                        elif attacker.attack_type == 'cache_poisoning':
                            # Cache Poisoning Attack - dua tahap
                            router = self.nodes[router_id]
                            
                            # Tahap 1: Kirim Interest normal untuk memicu Data dari producer
                            result = router.receive_interest(
                                attack['interest_name'],
                                attacker.node_id,
                                router.links[attacker.node_id]['face_id'],
                                is_attack=False  # Tidak terdeteksi sebagai serangan pada tahap ini
                            )
                            
                            # Tambahkan ke dataset
                            self.add_to_dataset(
                                'interest',  # Terlihat seperti Interest normal
                                attacker.node_id,
                                router_id,
                                attack['interest_name'],
                                len(attack['interest_name']) + 40,
                                False  # Tidak terdeteksi sebagai serangan
                            )
                            
                            # Kirim ke pcap
                            self.send_to_pcap(
                                'interest',
                                attacker.node_id,
                                router_id,
                                attack['interest_name'],
                                len(attack['interest_name']) + 40
                            )
                            
                            # Proses forwarding Interest normal
                            self.process_interest_forwarding(result, attack, router)
                            
                            # Tahap 2: Kirim data palsu sebelum data asli kembali
                            # Simulasikan delay untuk memastikan data palsu dikirim setelah Interest
                            threading.Timer(
                                0.5,  # Delay 500ms untuk simulasi
                                self.execute_cache_poisoning,
                                args=[attacker, router, attack['interest_name']]
                            ).start()
                    
                    # Jadwalkan serangan berikutnya
                    next_attacker_time[node_id] = current_time + (1.0 / attacker.attack_rate)
            
            # Cleanup PIT untuk semua router
            if current_time >= next_cleanup_time:
                for node_id, node in self.nodes.items():
                    if isinstance(node, NDNRouter):
                        node.cleanup_pit()
                
                next_cleanup_time = current_time + 1.0
            
            # Jeda kecil untuk mengurangi penggunaan CPU
            time.sleep(0.001)

    def execute_cache_poisoning(self, attacker, router, interest_name):
        """Eksekusi tahap kedua dari Cache Poisoning Attack"""
        if not self.running:
            return
        
        # Buat data palsu
        fake_data = f"POISONED_DATA_for_{interest_name}" + "X" * 1024
        fake_data_size = len(fake_data)
        
        # Log aktivitas
        attacker.log_activity(
            'cache_poisoning', 
            f"Sending poisoned data for {interest_name} to {router.node_id}",
            is_attack=True
        )
        
        # Tambahkan ke dataset
        self.add_to_dataset(
            'poisoned_data',
            attacker.node_id,
            router.node_id,
            interest_name,
            fake_data_size,
            True
        )
        
        # Kirim ke pcap
        self.send_to_pcap(
            'poisoned_data',
            attacker.node_id,
            router.node_id,
            interest_name,
            fake_data_size
        )
        
        # Router menerima data palsu
        router_face_id = router.links[attacker.node_id]['face_id']
        poison_result = router.receive_data(
            interest_name,
            fake_data,
            attacker.node_id,
            router_face_id
        )
        
        # Proses forwarding data palsu
        self.process_data_forwarding(poison_result, interest_name, fake_data, router)

    
    def process_interest_forwarding(self, result, interest, current_router):
        """Memproses forwarding Interest dari router ke router atau producer"""
        if result['status'] == 'forwarded':
            next_hop_id = result['next_hop']
            next_hop = self.nodes.get(next_hop_id)
            
            if not next_hop:
                return
            
            # Tambahkan ke dataset
            self.add_to_dataset(
                'interest_forward',
                current_router.node_id,
                next_hop_id,
                interest['interest_name'],
                len(interest['interest_name']) + 40,
                interest.get('is_attack', False)
            )
            
            # Kirim ke pcap
            self.send_to_pcap(
                'interest_forward',
                current_router.node_id,
                next_hop_id,
                interest['interest_name'],
                len(interest['interest_name']) + 40
            )
            
            # Jika next hop adalah producer, proses Interest
            if isinstance(next_hop, NDNProducer):
                face_id = next_hop.links[current_router.node_id]['face_id']
                data_result = next_hop.receive_interest(
                    interest['interest_name'],
                    current_router.node_id,
                    face_id
                )
                
                if data_result['status'] == 'sent':
                    # Producer mengirim Data packet kembali ke router
                    content_name = data_result['content_name']
                    content_data = data_result['content_data']
                    content_size = data_result['size']
                    
                    # Tambahkan ke dataset
                    self.add_to_dataset(
                        'data',
                        next_hop_id,
                        current_router.node_id,
                        content_name,
                        content_size,
                        False
                    )
                    
                    # Kirim ke pcap
                    self.send_to_pcap(
                        'data',
                        next_hop_id,
                        current_router.node_id,
                        content_name,
                        content_size
                    )
                    
                    # Router menerima Data packet
                    router_face_id = current_router.links[next_hop_id]['face_id']
                    forward_result = current_router.receive_data(
                        content_name,
                        content_data,
                        next_hop_id,
                        router_face_id
                    )
                    
                    # Proses forwarding Data jika perlu
                    self.process_data_forwarding(forward_result, content_name, content_data, current_router)
            
            # Jika next hop adalah router, teruskan Interest
            elif isinstance(next_hop, NDNRouter):
                face_id = next_hop.links[current_router.node_id]['face_id']
                next_result = next_hop.receive_interest(
                    interest['interest_name'],
                    current_router.node_id,
                    face_id,
                    interest.get('is_attack', False)
                )
                
                # Rekursif proses forwarding
                self.process_interest_forwarding(next_result, interest, next_hop)
    
    def process_data_forwarding(self, result, content_name, content_data, current_router):
        """Memproses forwarding Data dari router ke router atau consumer"""
        if result['status'] == 'forwarded':
            # Data diteruskan ke beberapa node
            for node_info in result['nodes']:
                node_id = node_info['node']
                face_id = node_info['face_id']
                node = self.nodes.get(node_id)
                
                if not node:
                    continue
                
                # Tambahkan ke dataset
                content_size = len(content_data)
                self.add_to_dataset(
                    'data_forward',
                    current_router.node_id,
                    node_id,
                    content_name,
                    content_size,
                    False
                )
                
                # Kirim ke pcap
                self.send_to_pcap(
                    'data_forward',
                    current_router.node_id,
                    node_id,
                    content_name,
                    content_size
                )
                
                # Jika node adalah consumer, proses Data
                if isinstance(node, NDNConsumer):
                    # Temukan Interest yang sesuai
                    # Dalam implementasi nyata, consumer akan melacak Interest yang dikirim
                    send_time = time.time() - 2.0  # Asumsi waktu pengiriman
                    node.receive_data(
                        content_name,
                        content_data,
                        current_router.node_id,
                        node.links[current_router.node_id]['face_id'],
                        send_time
                    )
                
                # Jika node adalah router, teruskan Data
                elif isinstance(node, NDNRouter):
                    forward_result = node.receive_data(
                        content_name,
                        content_data,
                        current_router.node_id,
                        node.links[current_router.node_id]['face_id']
                    )
                    
                    # Rekursif proses forwarding
                    self.process_data_forwarding(forward_result, content_name, content_data, node)
                
                # Jika node adalah attacker (untuk cache poisoning)
                elif isinstance(node, NDNAttacker) and node.attack_type == 'cache_poisoning':
                    poison_result = node.receive_data(
                        content_name,
                        content_data,
                        current_router.node_id,
                        node.links[current_router.node_id]['face_id']
                    )
                    
                    # Jika attacker mengirim data palsu
                    if poison_result.get('status') == 'poisoned':
                        fake_data = poison_result['content_data']
                        
                        # Tambahkan ke dataset
                        self.add_to_dataset(
                            'poisoned_data',
                            node_id,
                            current_router.node_id,
                            content_name,
                            len(fake_data),
                            True
                        )
                        
                        # Kirim ke pcap
                        self.send_to_pcap(
                            'poisoned_data',
                            node_id,
                            current_router.node_id,
                            content_name,
                            len(fake_data)
                        )
                        
                        # Router menerima data palsu
                        router_face_id = current_router.links[node_id]['face_id']
                        poison_forward = current_router.receive_data(
                            content_name,
                            fake_data,
                            node_id,
                            router_face_id
                        )
                        
                        # Proses forwarding data palsu
                        self.process_data_forwarding(poison_forward, content_name, fake_data, current_router)
    
    def handle_interest_timeout(self, interest, consumer):
        """Menangani timeout untuk Interest"""
        # Cek apakah simulasi masih berjalan
        if not self.running:
            return
        
        # Cek apakah Interest sudah terjawab (implementasi sederhana)
        # Dalam implementasi nyata, consumer akan melacak Interest yang belum terjawab
        if consumer.data_received < consumer.interests_sent:
            consumer.handle_timeout(interest['interest_name'])
            
            # Tambahkan ke dataset
            self.add_to_dataset(
                'timeout',
                consumer.node_id,
                interest['to_node'],
                interest['interest_name'],
                0,
                False
            )

    def collect_nfd_logs(self):
        """Mengumpulkan log NFD, CS, PIT, dan FIB dari semua node"""
        print(SECTION_HEADER("COLLECTING NFD LOGS"))
        
        # Buat direktori untuk log
        logs_dir = os.path.join(OUTPUT_DIR, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        
        # Inisialisasi variabel untuk menyimpan data log
        all_nfd_status = {}
        all_fib_data = {}
        all_cs_data = {}
        all_pit_data = {}
        
        # Kumpulkan log dari setiap node
        for node_id, node in self.nodes.items():
            # Untuk semua node (tidak hanya router), kita simpan status simulasi
            node_status = {
                'node_id': node_id,
                'node_type': node.node_type,
                'uptime': time.time() - node.start_time,
                'packet_count': node.packet_count,
                'byte_count': node.byte_count
            }
            
            # Simpan status node ke file
            with open(os.path.join(logs_dir, f"{node_id}_status.json"), 'w') as f:
                import json
                json.dump(node_status, f, indent=4)
            
            # Untuk router, kita kumpulkan data NFD
            if isinstance(node, NDNRouter):
                # Simpan status NFD simulasi
                nfd_status = node.get_nfd_status()
                all_nfd_status[node_id] = nfd_status
                
                with open(os.path.join(logs_dir, f"{node_id}_nfd_status.json"), 'w') as f:
                    import json
                    json.dump(nfd_status, f, indent=4)
                
                # Simpan data PIT
                pit_status = node.get_pit_status()
                all_pit_data[node_id] = pit_status
                
                with open(os.path.join(logs_dir, f"{node_id}_pit.json"), 'w') as f:
                    import json
                    json.dump(pit_status, f, indent=4)
                
                # Simpan data FIB
                fib_status = node.get_fib_status()
                all_fib_data[node_id] = fib_status
                
                with open(os.path.join(logs_dir, f"{node_id}_fib.json"), 'w') as f:
                    import json
                    json.dump(fib_status, f, indent=4)
                
                # Simpan data CS (Content Store)
                cs_data = {
                    'cs_size': len(node.cs),
                    'cs_max_size': node.cs_max_size,
                    'cs_hit_count': node.cs_hit_count,
                    'cs_miss_count': node.cs_miss_count,
                    'cs_hit_ratio': node.cs_hit_count / (node.cs_hit_count + node.cs_miss_count) if (node.cs_hit_count + node.cs_miss_count) > 0 else 0,
                    'entries': [{'name': name, 'expiry': data['expiry']} for name, data in node.cs.items()]
                }
                all_cs_data[node_id] = cs_data
                
                with open(os.path.join(logs_dir, f"{node_id}_cs.json"), 'w') as f:
                    import json
                    json.dump(cs_data, f, indent=4)
                
                # Jika node memiliki mininet_node, kumpulkan log dari NFD yang sebenarnya
                if node.mininet_node:
                    try:
                        # Dapatkan status NFD
                        nfd_status_output = node.mininet_node.cmd("nfdc status report")
                        with open(os.path.join(logs_dir, f"{node_id}_nfd_status.txt"), 'w') as f:
                            f.write(nfd_status_output)
                        
                        # Dapatkan FIB
                        fib_output = node.mininet_node.cmd("nfdc fib list")
                        with open(os.path.join(logs_dir, f"{node_id}_fib.txt"), 'w') as f:
                            f.write(fib_output)
                        
                        # Dapatkan CS
                        cs_output = node.mininet_node.cmd("nfdc cs info")
                        with open(os.path.join(logs_dir, f"{node_id}_cs.txt"), 'w') as f:
                            f.write(cs_output)
                        
                        # Dapatkan PIT (tidak ada command line untuk PIT, jadi kita gunakan nfd-status)
                        pit_output = node.mininet_node.cmd("nfd-status -v | grep -A 50 'PIT:'")
                        with open(os.path.join(logs_dir, f"{node_id}_pit.txt"), 'w') as f:
                            f.write(pit_output)
                        
                        # Dapatkan log NFD
                        nfd_log = node.mininet_node.cmd("cat /var/log/ndn/nfd.log")
                        with open(os.path.join(logs_dir, f"{node_id}_nfd.log"), 'w') as f:
                            f.write(nfd_log)
                        
                        # Dapatkan log NLSR jika ada
                        if hasattr(node, 'nlsr_process') and node.nlsr_process:
                            nlsr_log = node.mininet_node.cmd("cat /var/log/ndn/nlsr.log")
                            with open(os.path.join(logs_dir, f"{node_id}_nlsr.log"), 'w') as f:
                                f.write(nlsr_log)
                        
                        print(f"Collected logs for node {node_id}")
                    except Exception as e:
                        print(f"Error collecting logs for node {node_id}: {e}")
        
        # Gabungkan semua log ke dalam satu file untuk analisis
        try:
            # Simpan data gabungan dalam format JSON
            combined_data = {
                'nfd_status': all_nfd_status,
                'fib_data': all_fib_data,
                'cs_data': all_cs_data,
                'pit_data': all_pit_data
            }
            
            with open(os.path.join(logs_dir, "combined_data.json"), 'w') as f:
                import json
                json.dump(combined_data, f, indent=4)
            
            # Gabungkan log teks
            combined_log = ""
            for filename in os.listdir(logs_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(logs_dir, filename)
                    if os.path.isfile(filepath):
                        with open(filepath, 'r') as f:
                            content = f.read()
                            combined_log += f"\n\n===== {filename} =====\n\n"
                            combined_log += content
            
            with open(os.path.join(logs_dir, "combined_logs.txt"), 'w') as f:
                f.write(combined_log)
            
            print("Combined logs saved to logs/combined_logs.txt")
            print("Combined data saved to logs/combined_data.json")
            
            # Lakukan analisis dan simpan hasilnya
            self.analyze_simulation_data()
            
        except Exception as e:
            print(f"Error combining logs: {e}")

    def analyze_simulation_data(self):
        """Menganalisis data simulasi dan menyimpan hasilnya"""
        print(SECTION_HEADER("ANALYZING SIMULATION DATA"))
        
        # Buat direktori untuk analisis
        analysis_dir = os.path.join(OUTPUT_DIR, "analysis")
        os.makedirs(analysis_dir, exist_ok=True)
        
        # Konversi dataset ke DataFrame
        df = pd.DataFrame(self.dataset)
        
        try:
            # 1. Analisis distribusi tipe paket
            packet_type_dist = df['packet_type'].value_counts().reset_index()
            packet_type_dist.columns = ['packet_type', 'count']
            packet_type_dist.to_csv(os.path.join(analysis_dir, "packet_type_distribution.csv"), index=False)
            
            # 2. Analisis serangan vs normal
            attack_dist = df['is_attack'].value_counts().reset_index()
            attack_dist.columns = ['is_attack', 'count']
            attack_dist.to_csv(os.path.join(analysis_dir, "attack_distribution.csv"), index=False)
            
            # 3. Analisis performa router
            router_data = []
            for node_id, node in self.nodes.items():
                if isinstance(node, NDNRouter):
                    nfd_status = node.get_nfd_status()
                    router_data.append({
                        'node_id': node_id,
                        'cs_hit_ratio': nfd_status['performance']['cs_hit_ratio'],
                        'pit_satisfaction_ratio': nfd_status['performance']['pit_satisfaction_ratio'],
                        'cpu_utilization': nfd_status['performance']['cpu_utilization'],
                        'memory_utilization': nfd_status['performance']['memory_utilization'],
                        'pit_size': nfd_status['tables']['pit_size'],
                        'cs_size': nfd_status['tables']['cs_size'],
                        'fib_size': nfd_status['tables']['fib_size']
                    })
            
            router_df = pd.DataFrame(router_data)
            router_df.to_csv(os.path.join(analysis_dir, "router_performance.csv"), index=False)
            
            # 4. Analisis throughput dan delay
            throughput_df = df[['packet_type', 'throughput_kbps', 'delay_ms', 'is_attack']]
            throughput_df.to_csv(os.path.join(analysis_dir, "throughput_delay_analysis.csv"), index=False)
            
            # 5. Analisis aktivitas per node
            node_activity = df.groupby(['from_node', 'from_node_type']).size().reset_index(name='packet_count')
            node_activity.to_csv(os.path.join(analysis_dir, "node_activity.csv"), index=False)
            
            # 6. Analisis efektivitas serangan
            if 'attack' in df['packet_type'].values:
                attack_df = df[df['packet_type'] == 'attack']
                attack_effectiveness = {}
                
                # Untuk setiap router, hitung persentase CPU dan memori selama serangan
                for node_id, node in self.nodes.items():
                    if isinstance(node, NDNRouter):
                        router_attacks = attack_df[attack_df['to_node'] == node_id]
                        if not router_attacks.empty:
                            avg_cpu = router_attacks['cpu_utilization'].mean()
                            avg_mem = router_attacks['memory_utilization'].mean()
                            attack_effectiveness[node_id] = {
                                'avg_cpu_during_attack': avg_cpu,
                                'avg_memory_during_attack': avg_mem
                            }
                
                # Simpan hasil analisis efektivitas serangan
                with open(os.path.join(analysis_dir, "attack_effectiveness.json"), 'w') as f:
                    import json
                    json.dump(attack_effectiveness, f, indent=4)
            
            # 7. Analisis waktu simulasi
            time_analysis = {
                'start_time': self.start_time,
                'end_time': self.end_time,
                'duration': self.end_time - self.start_time,
                'first_packet_time': df['timestamp'].min(),
                'last_packet_time': df['timestamp'].max(),
                'packet_rate': len(df) / (self.end_time - self.start_time)
            }
            
            with open(os.path.join(analysis_dir, "time_analysis.json"), 'w') as f:
                import json
                json.dump(time_analysis, f, indent=4)
            
            # 8. Analisis topologi jaringan
            topology_analysis = {
                'node_count': len(self.nodes),
                'link_count': len(self.links),
                'router_count': sum(1 for node in self.nodes.values() if isinstance(node, NDNRouter)),
                'consumer_count': sum(1 for node in self.nodes.values() if isinstance(node, NDNConsumer)),
                'producer_count': sum(1 for node in self.nodes.values() if isinstance(node, NDNProducer)),
                'attacker_count': sum(1 for node in self.nodes.values() if isinstance(node, NDNAttacker)),
                'nodes': [{'id': node_id, 'type': node.node_type} for node_id, node in self.nodes.items()],
                'links': [{'node1': n1, 'node2': n2, 'delay': d, 'bandwidth': b} for n1, n2, d, b in self.links]
            }
            
            with open(os.path.join(analysis_dir, "topology_analysis.json"), 'w') as f:
                import json
                json.dump(topology_analysis, f, indent=4)
            
            print("Analysis completed and saved to analysis directory")
            
        except Exception as e:
            print(f"Error during analysis: {e}")
            import traceback
            traceback.print_exc()


    def add_to_dataset(self, packet_type, from_node, to_node, packet_name, packet_size, is_attack):
        """Menambahkan entri ke dataset"""
        timestamp = time.time()
        
        # Dapatkan informasi node
        from_node_obj = self.nodes.get(from_node)
        to_node_obj = self.nodes.get(to_node)
        
        if not from_node_obj or not to_node_obj:
            return
        
        # Dapatkan informasi link
        delay = '0ms'
        bandwidth = '0'
        
        if from_node in to_node_obj.links:
            link_info = to_node_obj.links[from_node]
            delay = link_info['delay']
            bandwidth = str(link_info['bandwidth'])
        
        # Konversi delay dari string ke float (ms)
        delay_ms = float(delay.replace('ms', ''))
        
        # Hitung throughput (dalam kbps) berdasarkan ukuran paket dan bandwidth
        throughput = 0
        if packet_size > 0 and float(bandwidth) > 0:
            # Throughput = (packet_size in bits) / (delay in seconds)
            throughput = (packet_size * 8) / (delay_ms / 1000) / 1000  # kbps
        
        # Batasi throughput oleh bandwidth
        throughput = min(throughput, float(bandwidth) * 1000)  # bandwidth dalam Mbps, throughput dalam kbps
        
        # Dapatkan informasi CPU dan memori untuk node tujuan
        cpu_util = 0
        memory_util = 0
        
        if isinstance(to_node_obj, NDNRouter):
            cpu_util = to_node_obj.cpu_util
            memory_util = to_node_obj.memory_util
        
        # Tambahkan entri ke dataset
        entry = {
            'timestamp': timestamp,
            'packet_type': packet_type,
            'from_node': from_node,
            'from_node_type': from_node_obj.node_type,
            'to_node': to_node,
            'to_node_type': to_node_obj.node_type,
            'packet_name': packet_name,
            'packet_size': packet_size,
            'delay_ms': delay_ms,
            'bandwidth_mbps': float(bandwidth),
            'throughput_kbps': throughput,
            'is_attack': 1 if is_attack else 0,
            'cpu_utilization': cpu_util,
            'memory_utilization': memory_util
        }
        
        self.dataset.append(entry)
    
    def save_dataset(self):
        """Menyimpan dataset ke file CSV"""
        print(SECTION_HEADER("SAVING SIMULATION RESULTS"))
        
        if not self.dataset:
            print("No data to save")
            return
        
        # Path untuk file dataset
        dataset_path = os.path.join(OUTPUT_DIR, "dataset", DATASET_FILE)
        
        # Konversi ke DataFrame
        df = pd.DataFrame(self.dataset)
        
        # Simpan ke CSV
        df.to_csv(dataset_path, index=False)
        
        print(f"Dataset saved to {dataset_path}")
        print(f"Total entries: {len(df)}")
        
        # Tampilkan statistik dasar
        packet_types = df['packet_type'].value_counts()
        attack_count = df['is_attack'].sum()
        normal_count = len(df) - attack_count
        
        print("\nPacket Type Distribution:")
        for packet_type, count in packet_types.items():
            print(f"  {packet_type}: {count} packets")
        
        print(f"\nNormal packets: {normal_count} ({normal_count/len(df)*100:.1f}%)")
        print(f"Attack packets: {attack_count} ({attack_count/len(df)*100:.1f}%)")
        
        # Simpan juga log aktivitas dari setiap node
        self.save_node_logs()
        
        # Simpan statistik node
        self.save_node_stats()
    
    def save_node_logs(self):
        """Menyimpan log aktivitas dari setiap node"""
        all_logs = []
        
        for node_id, node in self.nodes.items():
            for log in node.log_entries:
                log['node_id'] = node_id
                log['node_type'] = node.node_type
                all_logs.append(log)
        
        # Urutkan berdasarkan timestamp
        all_logs.sort(key=lambda x: x['timestamp'])
        
        # Path untuk file log
        log_path = os.path.join(OUTPUT_DIR, "raw_data", "node_activity_logs.csv")
        
        # Konversi ke DataFrame
        df = pd.DataFrame(all_logs)
        
        # Simpan ke CSV
        df.to_csv(log_path, index=False)
        
        print(f"Node activity logs saved to {log_path}")
        print(f"Total log entries: {len(df)}")
    
    def save_node_stats(self):
        """Menyimpan statistik dari setiap node"""
        # Statistik router
        router_stats = []
        for node_id, node in self.nodes.items():
            if isinstance(node, NDNRouter):
                stats = node.get_node_stats()
                nfd_stats = node.get_nfd_status()
                
                # Gabungkan statistik
                combined_stats = {**stats}
                combined_stats['cs_hit_ratio'] = nfd_stats['performance']['cs_hit_ratio']
                combined_stats['pit_satisfaction_ratio'] = nfd_stats['performance']['pit_satisfaction_ratio']
                combined_stats['cpu_utilization'] = nfd_stats['performance']['cpu_utilization']
                combined_stats['memory_utilization'] = nfd_stats['performance']['memory_utilization']
                
                router_stats.append(combined_stats)
        
        # Statistik consumer
        consumer_stats = []
        for node_id, node in self.nodes.items():
            if isinstance(node, NDNConsumer):
                stats = node.get_consumer_stats()
                consumer_stats.append(stats)
        
        # Statistik producer
        producer_stats = []
        for node_id, node in self.nodes.items():
            if isinstance(node, NDNProducer):
                stats = node.get_producer_stats()
                producer_stats.append(stats)
        
        # Statistik attacker
        attacker_stats = []
        for node_id, node in self.nodes.items():
            if isinstance(node, NDNAttacker):
                stats = node.get_attacker_stats()
                attacker_stats.append(stats)
        
        # Statistik face
        face_stats = []
        for node_id, node in self.nodes.items():
            for face_id, face in node.faces.items():
                stats = face.get_stats()
                stats['node_id'] = node_id
                face_stats.append(stats)
        
        # Path untuk file statistik
        router_stats_path = os.path.join(OUTPUT_DIR, "statistics", "router_stats.csv")
        consumer_stats_path = os.path.join(OUTPUT_DIR, "statistics", "consumer_stats.csv")
        producer_stats_path = os.path.join(OUTPUT_DIR, "statistics", "producer_stats.csv")
        attacker_stats_path = os.path.join(OUTPUT_DIR, "statistics", "attacker_stats.csv")
        face_stats_path = os.path.join(OUTPUT_DIR, "statistics", "face_stats.csv")
        
        # Konversi ke DataFrame dan simpan
        if router_stats:
            pd.DataFrame(router_stats).to_csv(router_stats_path, index=False)
            print(f"Router statistics saved to {router_stats_path}")
        
        if consumer_stats:
            pd.DataFrame(consumer_stats).to_csv(consumer_stats_path, index=False)
            print(f"Consumer statistics saved to {consumer_stats_path}")
        
        if producer_stats:
            pd.DataFrame(producer_stats).to_csv(producer_stats_path, index=False)
            print(f"Producer statistics saved to {producer_stats_path}")
        
        if attacker_stats:
            pd.DataFrame(attacker_stats).to_csv(attacker_stats_path, index=False)
            print(f"Attacker statistics saved to {attacker_stats_path}")
        
        if face_stats:
            pd.DataFrame(face_stats).to_csv(face_stats_path, index=False)
            print(f"Face statistics saved to {face_stats_path}")

    def start_minindn_cli(self):
        """Memulai CLI MiniNDN untuk interaksi langsung dengan node"""
        if not MININDN_AVAILABLE:
            print("MiniNDN tidak tersedia, CLI tidak dapat dijalankan")
            return False
        
        try:
            if hasattr(self, 'minindn') and self.minindn and hasattr(self, 'net') and self.net:
                print(SECTION_HEADER("STARTING MININDN CLI"))
                print("Memulai CLI MiniNDN. Ketik 'help' untuk melihat perintah yang tersedia.")
                print("Contoh perintah:")
                print("  r_core cmd nfdc status report  # Menampilkan status NFD pada node r_core")
                print("  r_info cmd nlsrc status        # Menampilkan status NLSR pada node r_info")
                print("  p_akad cmd nfd-status          # Menampilkan status NFD pada node p_akad")
                print("  c_mhs1 ping c_mhs2             # Ping dari c_mhs1 ke c_mhs2")
                print("  exit                           # Keluar dari CLI")
                
                # Mulai CLI MiniNDN
                MiniNDNCLI(self.net)
                return True
            else:
                print("MiniNDN belum diinisialisasi, CLI tidak dapat dijalankan")
                return False
        except Exception as e:
            print(f"Error memulai CLI MiniNDN: {e}")
            import traceback
            traceback.print_exc()
            return False

# ==============================
# SECTION: Fungsi Utama
# ==============================
def list_topologies():
    """Mencari dan menampilkan semua file topologi yang tersedia"""
    topology_files = []
    
    # Cari file topologi di direktori saat ini dan subdirektori
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.conf'):  # Sudah benar, tidak perlu filter 'topology'
                path = os.path.join(root, file)
                topology_files.append(path)
    
    # Tampilkan daftar topologi
    print(SECTION_HEADER("AVAILABLE TOPOLOGIES"))
    
    if not topology_files:
        print("No topology files found. Please create a topology file with .conf extension.")
        return None
    
    print("Found the following topology files:")
    for i, path in enumerate(topology_files, 1):
        print(f"{i}. {path}")
    
    # Minta pengguna memilih topologi
    selection = input("\nSelect a topology file (enter number): ")
    try:
        index = int(selection) - 1
        if 0 <= index < len(topology_files):
            selected_topology = topology_files[index]
            print(f"Selected topology: {selected_topology}")
            return selected_topology
        else:
            print("Invalid selection. Using default topology.")
            return topology_files[0]
    except ValueError:
        print("Invalid input. Using default topology.")
        return topology_files[0]


def main():
    """Fungsi utama program"""
    global OUTPUT_DIR
    
    # Tampilkan header
    print(NDN_HEADER)
    print(VERSION_INFO)
    
    # Parse argumen command line
    parser = argparse.ArgumentParser(description='NDN Simulation for Interest Flooding Attack')
    parser.add_argument('-t', '--topology', help='Path to topology file')
    parser.add_argument('-d', '--duration', type=int, default=SIMULATION_DURATION,
                       help=f'Simulation duration in seconds (default: {SIMULATION_DURATION})')
    parser.add_argument('-o', '--output', default=None,
                       help=f'Output directory (default: based on topology name)')
    parser.add_argument('-c', '--cli', action='store_true',
                       help='Start MiniNDN CLI after simulation')
    args = parser.parse_args()
    
    # Jika topologi tidak diberikan, tampilkan daftar topologi yang tersedia
    topology_file = args.topology
    if not topology_file:
        topology_file = list_topologies()
        if not topology_file:
            return
    
    # Update output directory berdasarkan nama file topologi jika tidak diberikan secara eksplisit
    if args.output:
        OUTPUT_DIR = args.output
    else:
        # Ekstrak nama file topologi tanpa path dan ekstensi
        topology_name = os.path.splitext(os.path.basename(topology_file))[0]
        OUTPUT_DIR = f"./output_{topology_name}"
        print(f"Output directory set to: {OUTPUT_DIR}")
    
    # Tampilkan referensi dan penjelasan
    print(REFERENCES)
    print(ATTACK_MODELS)
    print(NDN_COMPONENTS)
    
    # Buat dan jalankan simulasi
    simulation = NDNSimulation(topology_file)
    
    # Parse topologi
    if not simulation.parse_topology():
        print("Failed to parse topology. Exiting.")
        return
    
    # Jalankan simulasi
    simulation.run(args.duration, args.cli)

if __name__ == "__main__":
    main()

            
