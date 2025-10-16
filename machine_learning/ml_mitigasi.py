# NDN Attack Mitigation System - Enhanced Version
#!/usr/bin/env python3
# ndn_mitigasi_ml.py - Enhanced NDN Attack Mitigation System with Multiple ML Algorithms

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

# Machine Learning imports
from sklearn.ensemble import RandomForestClassifier, IsolationForest, HistGradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score, KFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve, auc,
    precision_recall_curve, average_precision_score
)
from sklearn.impute import SimpleImputer

# Abaikan warning matplotlib dan sklearn
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
║ [*] Version: 2.0.0                                                               ║
║ [*] Codename: NDNSecureML                                                        ║
║ [*] Author: Muhammad Raga Titipan (201012310022)                                 ║
║ [*] License: MIT                                                                 ║
║ [*] Build: 20250809-1530                                                         ║
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

class NDNMitigationSystem:
    """Sistem mitigasi serangan untuk jaringan NDN dengan multiple ML algorithms."""
    
    def __init__(self, dataset_path, output_dir="mitigation_results_final", algorithms=None):
        """
        Inisialisasi sistem mitigasi.
        
        Args:
            dataset_path (str): Path ke file dataset CSV
            output_dir (str): Direktori untuk menyimpan hasil mitigasi
            algorithms (list): Daftar algoritma ML yang akan digunakan
        """
        self.dataset_path = dataset_path
        self.output_dir = output_dir
        
        # Set default algorithms if not provided
        if algorithms is None:
            self.algorithms = ['random_forest', 'decision_tree', 'knn', 'isolation_forest', 'hist_gradient_boosting']
        else:
            self.algorithms = algorithms
        
        # Buat direktori output jika belum ada
        self._create_output_directories()
            
        # Inisialisasi atribut
        self.data = None
        self.mitigated_data = {}  # Dictionary untuk menyimpan hasil mitigasi dari setiap algoritma
        self.models = {}  # Dictionary untuk menyimpan model ML
        self.feature_importances = {}  # Dictionary untuk menyimpan feature importances
        
        # Statistik serangan
        self.attack_stats = {
            'interest_flooding': {'packet_count': 0, 'nodes': set(), 'percent_of_traffic': 0},
            'cache_poisoning': {'packet_count': 0, 'nodes': set(), 'percent_of_traffic': 0}
        }
        
        # Statistik mitigasi untuk setiap algoritma
        self.mitigation_stats = {algo: {
            'total_packets': {'before': 0, 'after': 0, 'reduction': 0},
            'attack_packets': {'before': 0, 'after': 0, 'reduction': 0},
            'legitimate_packets': {'before': 0, 'after': 0, 'reduction': 0},
            'metrics': {}  # Untuk menyimpan metrik evaluasi
        } for algo in self.algorithms}
        
        # Parameter untuk setiap algoritma
        self.ml_params = {
            'random_forest': {
                'n_estimators': 100,
                'max_depth': 10,
                'random_state': 42
            },
            'decision_tree': {
                'max_depth': 10,
                'random_state': 42
            },
            'knn': {
                'n_neighbors': 5,
                'weights': 'distance'
            },
            'isolation_forest': {
                'contamination': 0.05,
                'random_state': 42
            },
            'hist_gradient_boosting': {
                'max_iter': 100,
                'learning_rate': 0.1,
                'max_depth': 10,
                'random_state': 42
            }
        }
        
        # Untuk preprocessing
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.imputer = SimpleImputer(strategy='median')
        
    def _create_output_directories(self):
        """Buat direktori output dan subdirektori untuk setiap algoritma."""
        # Buat direktori output utama
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"[+] Membuat direktori output: {self.output_dir}")
            
        # Buat subdirektori untuk visualisasi
        viz_dir = f"{self.output_dir}/visualizations"
        if not os.path.exists(viz_dir):
            os.makedirs(viz_dir)
            
        # Buat subdirektori untuk setiap algoritma
        for algo in self.algorithms:
            algo_dir = f"{self.output_dir}/{algo}"
            if not os.path.exists(algo_dir):
                os.makedirs(algo_dir)
                
            # Subdirektori untuk visualisasi algoritma
            algo_viz_dir = f"{viz_dir}/{algo}"
            if not os.path.exists(algo_viz_dir):
                os.makedirs(algo_viz_dir)
    
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
                
                # Periksa kembali setelah imputasi
                missing_after = self.data[required_columns].isnull().sum().sum()
                if missing_after > 0:
                    print(f"[!] Peringatan: Masih ada {missing_after} nilai hilang setelah imputasi")
                else:
                    print("[+] Semua missing values berhasil ditangani")
            
            # Konversi tipe data
            if 'timestamp' in self.data.columns:
                self.data['datetime'] = pd.to_datetime(self.data['timestamp'], unit='s')
            
            # Pastikan kolom is_attack adalah numerik
            if 'is_attack' in self.data.columns:
                self.data['is_attack'] = self.data['is_attack'].astype(int)
                
            # Set mitigation stats untuk semua algoritma
            for algo in self.algorithms:
                self.mitigation_stats[algo]['total_packets']['before'] = len(self.data)
                self.mitigation_stats[algo]['attack_packets']['before'] = len(self.data[self.data['is_attack'] == 1])
                self.mitigation_stats[algo]['legitimate_packets']['before'] = len(self.data[self.data['is_attack'] == 0])
            
            # Tambahkan kolom untuk tipe serangan spesifik
            self._identify_attack_types()
            
            return True
        except Exception as e:
            print(f"[!] Error saat memuat dataset: {e}")
            return False
    
    def _identify_attack_types(self):
        """Identifikasi tipe serangan spesifik (Interest Flooding vs Cache Poisoning)."""
        # Inisialisasi kolom attack_type dengan 'normal'
        self.data['attack_type'] = 'normal'
        
        # Identifikasi Interest Flooding Attack (IFA)
        ifa_mask = (
            (self.data['is_attack'] == 1) & 
            (self.data['packet_type'].isin(['interest', 'attack'])) &
            (self.data['packet_name'].str.contains('nonexistent', case=False, na=False))
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
        
        # Analisis distribusi temporal
        self._analyze_temporal_distribution()
        
        # Analisis distribusi ukuran paket
        self._analyze_packet_size_distribution()
        
        # Analisis distribusi delay
        self._analyze_delay_distribution()
        
        # Analisis korelasi antar fitur
        self._analyze_feature_correlations()
        
        # Tampilkan ringkasan deteksi
        self._display_attack_summary()
    
    def _analyze_temporal_distribution(self):
        """Analisis distribusi temporal paket."""
        print("\n[*] Analisis distribusi temporal paket:")
        
        # Pastikan kolom datetime ada
        if 'datetime' not in self.data.columns:
            self.data['datetime'] = pd.to_datetime(self.data['timestamp'], unit='s')
        
        # Hitung jumlah paket per detik
        packets_per_second = self.data.groupby(self.data['datetime'].dt.floor('S')).size()
        
        # Uji distribusi Poisson
        lambda_est = packets_per_second.mean()
        poisson_dist = stats.poisson(lambda_est)
        
        # Hitung histogram empiris
        hist, bin_edges = np.histogram(packets_per_second, bins=20, density=True)
        bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2
        
        # Hitung nilai PMF Poisson untuk bin_centers
        poisson_pmf = poisson_dist.pmf(np.round(bin_centers).astype(int))
        
        # Uji kecocokan dengan Kolmogorov-Smirnov
        ks_stat, ks_pvalue = stats.kstest(packets_per_second, poisson_dist.cdf)
        
        print(f"    - Rata-rata paket per detik: {lambda_est:.2f}")
        print(f"    - Uji Kolmogorov-Smirnov untuk distribusi Poisson: stat={ks_stat:.4f}, p-value={ks_pvalue:.4f}")
        
        if ks_pvalue < 0.05:
            print("    - Distribusi temporal TIDAK mengikuti distribusi Poisson (p < 0.05)")
            
            # Coba distribusi lain
            # Uji distribusi Normal
            norm_params = stats.norm.fit(packets_per_second)
            norm_dist = stats.norm(*norm_params)
            ks_stat_norm, ks_pvalue_norm = stats.kstest(packets_per_second, norm_dist.cdf)
            
            # Uji distribusi Exponential
            exp_params = stats.expon.fit(packets_per_second)
            exp_dist = stats.expon(*exp_params)
            ks_stat_exp, ks_pvalue_exp = stats.kstest(packets_per_second, exp_dist.cdf)
            
            print(f"    - Uji distribusi Normal: stat={ks_stat_norm:.4f}, p-value={ks_pvalue_norm:.4f}")
            print(f"    - Uji distribusi Exponential: stat={ks_stat_exp:.4f}, p-value={ks_pvalue_exp:.4f}")
            
            # Tentukan distribusi terbaik
            distributions = {
                'Poisson': ks_pvalue,
                'Normal': ks_pvalue_norm,
                'Exponential': ks_pvalue_exp
            }
            best_dist = max(distributions.items(), key=lambda x: x[1])
            print(f"    - Distribusi terbaik: {best_dist[0]} (p-value={best_dist[1]:.4f})")
        else:
            print("    - Distribusi temporal mengikuti distribusi Poisson (p >= 0.05)")
    
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
    
    def _analyze_feature_correlations(self):
        """Analisis korelasi antar fitur numerik."""
        print("\n[*] Analisis korelasi antar fitur:")
        
        # Pilih fitur numerik
        numeric_features = ['packet_size', 'delay_ms', 'bandwidth_mbps', 'is_attack']
        if 'throughput_kbps' in self.data.columns:
            numeric_features.append('throughput_kbps')
        if 'cpu_utilization' in self.data.columns:
            numeric_features.append('cpu_utilization')
        if 'memory_utilization' in self.data.columns:
            numeric_features.append('memory_utilization')
        
        # Hitung korelasi
        corr_matrix = self.data[numeric_features].corr()
        
        # Tampilkan korelasi dengan is_attack
        attack_corr = corr_matrix['is_attack'].sort_values(ascending=False)
        print("    - Korelasi fitur dengan is_attack:")
        for feature, corr in attack_corr.items():
            if feature != 'is_attack':
                print(f"      * {feature}: {corr:.4f}")
    
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
    
    def prepare_features(self):
        """Persiapkan fitur untuk model machine learning."""
        print(SECTION_HEADER("Persiapan Fitur"))
        
        # Pilih fitur kategorik untuk encoding
        categorical_features = ['packet_type', 'from_node', 'from_node_type', 'to_node', 'to_node_type']
        
        # Encode fitur kategorik
        for feature in categorical_features:
            if feature in self.data.columns:
                le = LabelEncoder()
                self.data[f'{feature}_encoded'] = le.fit_transform(self.data[feature])
                self.label_encoders[feature] = le
                print(f"[+] Encoding fitur '{feature}' selesai: {len(le.classes_)} kelas unik")
        
        # Ekstrak nama prefix dari packet_name dengan penanganan error
        self.data['prefix'] = self.data['packet_name'].apply(
            lambda x: x.split('/')[1] if isinstance(x, str) and '/' in x and len(x.split('/')) > 1 else 'unknown'
        )
        self.data['prefix_encoded'] = LabelEncoder().fit_transform(self.data['prefix'])
        
        # Fitur tambahan dengan penanganan nilai yang hilang
        # 1. Apakah packet_name mengandung 'nonexistent'
        self.data['is_nonexistent'] = self.data['packet_name'].str.contains('nonexistent', case=False, na=False).astype(int)
        
        # 2. Rasio ukuran paket terhadap rata-rata ukuran untuk tipe paket tersebut dengan penanganan pembagian dengan nol
        avg_size_by_type = self.data.groupby('packet_type')['packet_size'].transform('mean')
        # Hindari pembagian dengan nol
        avg_size_by_type = avg_size_by_type.replace(0, 1)  # Ganti nilai 0 dengan 1 untuk menghindari pembagian dengan nol
        self.data['size_ratio'] = self.data['packet_size'] / avg_size_by_type
        
        # 3. Hitung rate paket per node sumber dengan penanganan pembagian dengan nol
        self.data['packet_rate'] = self.data.groupby('from_node')['timestamp'].transform(
            lambda x: len(x) / (x.max() - x.min()) if x.max() > x.min() else 0
        )
        
        # Pilih fitur untuk model
        self.feature_columns = [
            'packet_type_encoded', 'from_node_encoded', 'from_node_type_encoded',
            'to_node_encoded', 'to_node_type_encoded', 'prefix_encoded',
            'packet_size', 'delay_ms', 'bandwidth_mbps', 'is_nonexistent',
            'size_ratio', 'packet_rate'
        ]
        
        if 'throughput_kbps' in self.data.columns:
            self.feature_columns.append('throughput_kbps')
        if 'cpu_utilization' in self.data.columns:
            self.feature_columns.append('cpu_utilization')
        if 'memory_utilization' in self.data.columns:
            self.feature_columns.append('memory_utilization')
        
        # Target variable
        self.target_column = 'is_attack'
        
        print(f"[+] Fitur yang digunakan: {len(self.feature_columns)}")
        print(f"[+] Fitur yang dipilih: {', '.join(self.feature_columns)}")
        
        # Periksa dan tangani missing values
        print("[+] Memeriksa dan menangani missing values...")
        missing_values = self.data[self.feature_columns].isnull().sum()
        if missing_values.sum() > 0:
            print("    - Ditemukan missing values:")
            for feature, count in missing_values[missing_values > 0].items():
                print(f"      * {feature}: {count} nilai hilang")
            
            # Imputasi dengan nilai median untuk fitur numerik
            numeric_features = [
                'packet_size', 'delay_ms', 'bandwidth_mbps', 'size_ratio', 'packet_rate'
            ]
            if 'throughput_kbps' in self.data.columns:
                numeric_features.append('throughput_kbps')
            if 'cpu_utilization' in self.data.columns:
                numeric_features.append('cpu_utilization')
            if 'memory_utilization' in self.data.columns:
                numeric_features.append('memory_utilization')
            
            # Gunakan SimpleImputer untuk mengisi missing values
            if any(feature in missing_values[missing_values > 0].index for feature in numeric_features):
                numeric_data = self.data[numeric_features].values
                imputed_data = self.imputer.fit_transform(numeric_data)
                self.data[numeric_features] = imputed_data
                print(f"      * Mengisi fitur numerik dengan nilai median")
            
            # Untuk fitur kategorikal, isi dengan modus (nilai yang paling sering muncul)
            categorical_features = [col for col in self.feature_columns if col.endswith('_encoded')]
            for feature in categorical_features:
                if feature in missing_values[missing_values > 0].index:
                    mode_value = self.data[feature].mode()[0]
                    self.data[feature] = self.data[feature].fillna(mode_value)
                    print(f"      * Mengisi {feature} dengan nilai modus: {mode_value}")
            
            # Periksa kembali setelah imputasi
            missing_after = self.data[self.feature_columns].isnull().sum().sum()
            if missing_after > 0:
                print(f"    - Peringatan: Masih terdapat {missing_after} nilai hilang setelah imputasi")
                
                # Jika masih ada missing values, hapus baris yang bermasalah
                self.data = self.data.dropna(subset=self.feature_columns)
                print(f"    - Menghapus {missing_values.sum() - missing_after} baris dengan missing values")
                print(f"    - Jumlah data setelah pembersihan: {len(self.data)}")
            else:
                print("    - Semua missing values berhasil ditangani")
        else:
            print("    - Tidak ditemukan missing values")
        
        # Normalisasi fitur numerik
        numeric_features = [
            'packet_size', 'delay_ms', 'bandwidth_mbps', 'size_ratio', 'packet_rate'
        ]
        if 'throughput_kbps' in self.data.columns:
            numeric_features.append('throughput_kbps')
        if 'cpu_utilization' in self.data.columns:
            numeric_features.append('cpu_utilization')
        if 'memory_utilization' in self.data.columns:
            numeric_features.append('memory_utilization')
        
        # Tangani nilai tak terhingga
        for feature in numeric_features:
            self.data[feature] = self.data[feature].replace([np.inf, -np.inf], np.nan)
            if self.data[feature].isnull().sum() > 0:
                self.data[feature] = self.data[feature].fillna(self.data[feature].median())
        
        self.data[numeric_features] = self.scaler.fit_transform(self.data[numeric_features])
        print(f"[+] Normalisasi fitur numerik selesai")
        
        # Split data untuk training dan testing
        X = self.data[self.feature_columns]
        y = self.data[self.target_column]
        
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"[+] Data dibagi untuk training ({len(self.X_train)} sampel) dan testing ({len(self.X_test)} sampel)")
    
    def train_models(self):
        """Latih model machine learning."""
        print(SECTION_HEADER("Pelatihan Model"))
        
        try:
            # Random Forest
            if 'random_forest' in self.algorithms:
                print("[+] Melatih model Random Forest...")
                rf_model = RandomForestClassifier(
                    n_estimators=self.ml_params['random_forest']['n_estimators'],
                    max_depth=self.ml_params['random_forest']['max_depth'],
                    random_state=self.ml_params['random_forest']['random_state']
                )
                rf_model.fit(self.X_train, self.y_train)
                self.models['random_forest'] = rf_model
                
                # Simpan feature importances
                self.feature_importances['random_forest'] = dict(zip(self.feature_columns, rf_model.feature_importances_))
                
                # Evaluasi model
                self._evaluate_model('random_forest')
            
            # Decision Tree
            if 'decision_tree' in self.algorithms:
                print("[+] Melatih model Decision Tree...")
                dt_model = DecisionTreeClassifier(
                    max_depth=self.ml_params['decision_tree']['max_depth'],
                    random_state=self.ml_params['decision_tree']['random_state']
                )
                dt_model.fit(self.X_train, self.y_train)
                self.models['decision_tree'] = dt_model
                
                # Simpan feature importances
                self.feature_importances['decision_tree'] = dict(zip(self.feature_columns, dt_model.feature_importances_))
                
                # Evaluasi model
                self._evaluate_model('decision_tree')
            
            # K-Nearest Neighbors
            if 'knn' in self.algorithms:
                print("[+] Melatih model K-Nearest Neighbors...")
                knn_model = KNeighborsClassifier(
                    n_neighbors=self.ml_params['knn']['n_neighbors'],
                    weights=self.ml_params['knn']['weights']
                )
                knn_model.fit(self.X_train, self.y_train)
                self.models['knn'] = knn_model
                
                # Evaluasi model
                self._evaluate_model('knn')
            
            # Histogram-based Gradient Boosting
            if 'hist_gradient_boosting' in self.algorithms:
                print("[+] Melatih model Histogram-based Gradient Boosting...")
                hgb_model = HistGradientBoostingClassifier(
                    max_iter=self.ml_params['hist_gradient_boosting']['max_iter'],
                    learning_rate=self.ml_params['hist_gradient_boosting']['learning_rate'],
                    max_depth=self.ml_params['hist_gradient_boosting']['max_depth'],
                    random_state=self.ml_params['hist_gradient_boosting']['random_state']
                )
                hgb_model.fit(self.X_train, self.y_train)
                self.models['hist_gradient_boosting'] = hgb_model
                
                # Evaluasi model
                self._evaluate_model('hist_gradient_boosting')
            
            # Isolation Forest (untuk deteksi anomali)
            if 'isolation_forest' in self.algorithms:
                print("[+] Melatih model Isolation Forest...")
                if_model = IsolationForest(
                    contamination=self.ml_params['isolation_forest']['contamination'],
                    random_state=self.ml_params['isolation_forest']['random_state']
                )
                if_model.fit(self.X_train)
                self.models['isolation_forest'] = if_model
                
                # Evaluasi model anomali
                self._evaluate_anomaly_model('isolation_forest')
        
        except Exception as e:
            print(f"[!] Error saat melatih model: {e}")
            print("[!] Mencoba mendiagnosis masalah...")
            
            # Periksa apakah masih ada missing values
            missing_values = self.X_train.isnull().sum()
            if missing_values.sum() > 0:
                print(f"    - Ditemukan {missing_values.sum()} missing values di data training")
                for feature, count in missing_values[missing_values > 0].items():
                    print(f"      * {feature}: {count} nilai hilang")
            
            # Periksa apakah ada nilai tak terhingga
            inf_values = np.isinf(self.X_train.values).sum()
            if inf_values > 0:
                print(f"    - Ditemukan {inf_values} nilai tak terhingga di data training")
            
            # Tampilkan saran
            print("[!] Saran perbaikan:")
            print("    - Pastikan semua missing values telah ditangani")
            print("    - Periksa perhitungan fitur yang mungkin menghasilkan NaN atau Inf")
            print("    - Pertimbangkan untuk menggunakan algoritma yang toleran terhadap missing values")
            print("    - Coba jalankan program dengan opsi --analyze-only untuk memeriksa dataset")
            
            # Coba gunakan model yang toleran terhadap missing values
            print("[+] Mencoba menggunakan model yang toleran terhadap missing values...")
            try:
                print("[+] Melatih model Histogram-based Gradient Boosting (toleran terhadap missing values)...")
                hgb_model = HistGradientBoostingClassifier(
                    max_iter=100,
                    learning_rate=0.1,
                    max_depth=10,
                    random_state=42
                )
                hgb_model.fit(self.X_train, self.y_train)
                self.models['hist_gradient_boosting'] = hgb_model
                
                # Evaluasi model
                self._evaluate_model('hist_gradient_boosting')
                
                # Tambahkan ke daftar algoritma jika belum ada
                if 'hist_gradient_boosting' not in self.algorithms:
                    self.algorithms.append('hist_gradient_boosting')
                    self.mitigation_stats['hist_gradient_boosting'] = {
                        'total_packets': {'before': len(self.data), 'after': 0, 'reduction': 0},
                        'attack_packets': {'before': len(self.data[self.data['is_attack'] == 1]), 'after': 0, 'reduction': 0},
                        'legitimate_packets': {'before': len(self.data[self.data['is_attack'] == 0]), 'after': 0, 'reduction': 0},
                        'metrics': {}
                    }
                    
                print("[+] Model berhasil dilatih dengan Histogram-based Gradient Boosting")
            except Exception as e:
                print(f"[!] Error saat melatih model alternatif: {e}")
                print("[!] Tidak dapat melatih model. Silakan periksa dataset dan coba lagi.")
                return False
        
        return True

    def _evaluate_model(self, algorithm):
        """Evaluasi model klasifikasi."""
        model = self.models[algorithm]
        
        # Prediksi pada data testing
        y_pred = model.predict(self.X_test)
        
        # Hitung metrik
        accuracy = accuracy_score(self.y_test, y_pred)
        precision = precision_score(self.y_test, y_pred)
        recall = recall_score(self.y_test, y_pred)
        f1 = f1_score(self.y_test, y_pred)
        
        # Confusion Matrix
        cm = confusion_matrix(self.y_test, y_pred)
        
        # ROC Curve dan AUC (jika model mendukung predict_proba)
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(self.X_test)[:, 1]
            fpr, tpr, _ = roc_curve(self.y_test, y_prob)
            auc_score = auc(fpr, tpr)
        else:
            auc_score = None
        
        # Simpan metrik
        self.mitigation_stats[algorithm]['metrics'] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm,
            'auc': auc_score
        }
        
        # Tampilkan hasil
        print(f"\n[*] Evaluasi model {algorithm.upper()}:")
        print(f"    - Accuracy: {accuracy:.4f}")
        print(f"    - Precision: {precision:.4f}")
        print(f"    - Recall: {recall:.4f}")
        print(f"    - F1-Score: {f1:.4f}")
        if auc_score:
            print(f"    - AUC: {auc_score:.4f}")
        
        # Cross-validation
        cv_scores = cross_val_score(model, self.X_train, self.y_train, cv=5, scoring='f1')
        print(f"    - Cross-validation F1 (5-fold): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    
    def _evaluate_anomaly_model(self, algorithm):
        """Evaluasi model deteksi anomali."""
        model = self.models[algorithm]
        
        # Prediksi pada data testing (untuk Isolation Forest, -1 adalah anomali, 1 adalah normal)
        # Konversi ke format yang sama dengan target: 1 untuk anomali, 0 untuk normal
        anomaly_pred = np.where(model.predict(self.X_test) == -1, 1, 0)
        
        # Hitung metrik dengan asumsi bahwa is_attack=1 adalah anomali
        accuracy = accuracy_score(self.y_test, anomaly_pred)
        precision = precision_score(self.y_test, anomaly_pred)
        recall = recall_score(self.y_test, anomaly_pred)
        f1 = f1_score(self.y_test, anomaly_pred)
        
        # Confusion Matrix
        cm = confusion_matrix(self.y_test, anomaly_pred)
        
        # Simpan metrik
        self.mitigation_stats[algorithm]['metrics'] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm,
            'auc': None
        }
        
        # Tampilkan hasil
        print(f"\n[*] Evaluasi model {algorithm.upper()}:")
        print(f"    - Accuracy: {accuracy:.4f}")
        print(f"    - Precision: {precision:.4f}")
        print(f"    - Recall: {recall:.4f}")
        print(f"    - F1-Score: {f1:.4f}")
    
    def apply_mitigation(self):
        """Terapkan strategi mitigasi pada dataset menggunakan model yang telah dilatih."""
        print(SECTION_HEADER("Penerapan Mitigasi"))
        
        # Terapkan mitigasi untuk setiap algoritma
        for algorithm in self.algorithms:
            if algorithm not in self.models:
                print(f"[!] Model {algorithm} tidak tersedia. Melewati mitigasi untuk algoritma ini.")
                continue
                
            print(f"[+] Menerapkan mitigasi dengan {algorithm.upper()}...")
            
            # Salin dataset asli
            mitigated_data = self.data.copy()
            
            # Prediksi pada seluruh dataset
            X_full = mitigated_data[self.feature_columns]
            
            if algorithm == 'isolation_forest':
                # Untuk Isolation Forest, -1 adalah anomali, 1 adalah normal
                # Konversi ke format yang sama dengan target: 1 untuk anomali, 0 untuk normal
                predictions = np.where(self.models[algorithm].predict(X_full) == -1, 1, 0)
            else:
                predictions = self.models[algorithm].predict(X_full)
            
            # Tambahkan kolom prediksi
            mitigated_data[f'predicted_attack_{algorithm}'] = predictions
            
            # Identifikasi paket yang akan diblokir (predicted_attack = 1)
            blocked_mask = mitigated_data[f'predicted_attack_{algorithm}'] == 1
            
            # Hitung jumlah paket yang akan diblokir
            blocked_packets = mitigated_data[blocked_mask].shape[0]
            blocked_attack_packets = mitigated_data[blocked_mask & (mitigated_data['is_attack'] == 1)].shape[0]
            blocked_legitimate_packets = mitigated_data[blocked_mask & (mitigated_data['is_attack'] == 0)].shape[0]
            
            print(f"    - Total paket yang diblokir: {blocked_packets}")
            print(f"    - Paket serangan yang diblokir: {blocked_attack_packets}")
            print(f"    - Paket legitimate yang diblokir: {blocked_legitimate_packets}")
            
            # Hapus paket yang diblokir untuk membuat dataset hasil mitigasi
            mitigated_result = mitigated_data[~blocked_mask].copy()
            
            # Simpan hasil mitigasi
            self.mitigated_data[algorithm] = mitigated_result
            
            # Update statistik mitigasi
            self.mitigation_stats[algorithm]['total_packets']['after'] = len(mitigated_result)
            self.mitigation_stats[algorithm]['attack_packets']['after'] = len(mitigated_result[mitigated_result['is_attack'] == 1])
            self.mitigation_stats[algorithm]['legitimate_packets']['after'] = len(mitigated_result[mitigated_result['is_attack'] == 0])
            
            # Hitung persentase pengurangan
            if self.mitigation_stats[algorithm]['total_packets']['before'] > 0:
                self.mitigation_stats[algorithm]['total_packets']['reduction'] = (
                    (self.mitigation_stats[algorithm]['total_packets']['before'] - self.mitigation_stats[algorithm]['total_packets']['after']) / 
                    self.mitigation_stats[algorithm]['total_packets']['before'] * 100
                )
            
            if self.mitigation_stats[algorithm]['attack_packets']['before'] > 0:
                self.mitigation_stats[algorithm]['attack_packets']['reduction'] = (
                    (self.mitigation_stats[algorithm]['attack_packets']['before'] - self.mitigation_stats[algorithm]['attack_packets']['after']) / 
                    self.mitigation_stats[algorithm]['attack_packets']['before'] * 100
                )
            
            if self.mitigation_stats[algorithm]['legitimate_packets']['before'] > 0:
                self.mitigation_stats[algorithm]['legitimate_packets']['reduction'] = (
                    (self.mitigation_stats[algorithm]['legitimate_packets']['before'] - self.mitigation_stats[algorithm]['legitimate_packets']['after']) / 
                    self.mitigation_stats[algorithm]['legitimate_packets']['before'] * 100
                )
            
            # Simpan dataset hasil mitigasi
            mitigated_result.to_csv(f"{self.output_dir}/{algorithm}/mitigated_dataset.csv", index=False)
            print(f"    - Dataset hasil mitigasi disimpan di {self.output_dir}/{algorithm}/mitigated_dataset.csv")
            
            # Tampilkan ringkasan hasil mitigasi
            self._display_mitigation_summary(algorithm)
    
    def _display_mitigation_summary(self, algorithm):
        """Tampilkan ringkasan hasil mitigasi untuk algoritma tertentu."""
        print(f"\n[*] Ringkasan Hasil Mitigasi dengan {algorithm.upper()}:")
        
        print("    - Statistik Paket:")
        print(f"      * Total paket sebelum: {self.mitigation_stats[algorithm]['total_packets']['before']}")
        print(f"      * Total paket sesudah: {self.mitigation_stats[algorithm]['total_packets']['after']}")
        print(f"      * Pengurangan: {self.mitigation_stats[algorithm]['total_packets']['reduction']:.2f}%")
        
        print("    - Paket Serangan:")
        print(f"      * Paket serangan sebelum: {self.mitigation_stats[algorithm]['attack_packets']['before']}")
        print(f"      * Paket serangan sesudah: {self.mitigation_stats[algorithm]['attack_packets']['after']}")
        print(f"      * Pengurangan: {self.mitigation_stats[algorithm]['attack_packets']['reduction']:.2f}%")
        
        print("    - Paket Legitimate:")
        print(f"      * Paket legitimate sebelum: {self.mitigation_stats[algorithm]['legitimate_packets']['before']}")
        print(f"      * Paket legitimate sesudah: {self.mitigation_stats[algorithm]['legitimate_packets']['after']}")
        print(f"      * Pengurangan: {self.mitigation_stats[algorithm]['legitimate_packets']['reduction']:.2f}%")
        
        # Hitung metrik efektivitas
        if self.mitigation_stats[algorithm]['attack_packets']['before'] > 0:
            attack_reduction = self.mitigation_stats[algorithm]['attack_packets']['reduction']
        else:
            attack_reduction = 0
            
        if self.mitigation_stats[algorithm]['legitimate_packets']['before'] > 0:
            legitimate_reduction = self.mitigation_stats[algorithm]['legitimate_packets']['reduction']
        else:
            legitimate_reduction = 0
            
        print("    - Metrik Efektivitas:")
        print(f"      * Efektivitas mitigasi serangan: {attack_reduction:.2f}%")
        print(f"      * Dampak pada traffic legitimate: {legitimate_reduction:.2f}%")
        
        # Hitung false positive dan false negative dari confusion matrix
        if 'confusion_matrix' in self.mitigation_stats[algorithm]['metrics']:
            cm = self.mitigation_stats[algorithm]['metrics']['confusion_matrix']
            tn, fp, fn, tp = cm.ravel()
            
            print("    - Metrik Evaluasi Detail:")
            print(f"      * True Positives: {tp}")
            print(f"      * False Positives: {fp}")
            print(f"      * True Negatives: {tn}")
            print(f"      * False Negatives: {fn}")
            
            # Hitung metrik tambahan
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False Positive Rate
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0  # False Negative Rate
            
            print(f"      * False Positive Rate: {fpr:.4f}")
            print(f"      * False Negative Rate: {fnr:.4f}")
    
    def generate_visualizations(self):
        """Buat visualisasi hasil analisis dan mitigasi."""
        print(SECTION_HEADER("Visualisasi Hasil"))
        
        try:
            # Buat direktori visualisasi jika belum ada
            os.makedirs(f"{self.output_dir}/visualizations", exist_ok=True)
            for algo in self.algorithms:
                if algo in self.models:
                    os.makedirs(f"{self.output_dir}/visualizations/{algo}", exist_ok=True)
            
            # Import traceback untuk debugging
            import traceback
            
            # Coba buat setiap visualisasi secara terpisah dengan penanganan error
            visualization_functions = [
                ("distribusi traffic", self._plot_traffic_distribution),
                ("distribusi tipe paket", self._plot_packet_type_distribution),
                ("distribusi ukuran paket", self._plot_packet_size_distribution),
                ("distribusi delay", self._plot_delay_distribution),
                ("korelasi antar fitur", self._plot_feature_correlations),
                ("perbandingan algoritma", self._plot_algorithm_comparison),
                ("ROC curves", self._plot_roc_curves),
                ("feature importance", self._plot_feature_importance),
                ("confusion matrices", self._plot_confusion_matrices),
                ("perbandingan mitigasi", self._plot_mitigation_comparison)
            ]
            
            success_count = 0
            for viz_name, viz_func in visualization_functions:
                try:
                    print(f"[+] Membuat visualisasi {viz_name}...")
                    viz_func()
                    success_count += 1
                except Exception as e:
                    print(f"[!] Error saat membuat visualisasi {viz_name}: {e}")
                    traceback.print_exc()  # Tambahkan ini untuk debug
                    print("[!] Melanjutkan dengan visualisasi berikutnya...")
            
            print(f"[+] {success_count} dari {len(visualization_functions)} visualisasi berhasil dibuat")
            print(f"[+] Visualisasi disimpan di direktori {self.output_dir}/visualizations")
            
        except Exception as e:
            print(f"[!] Error saat membuat visualisasi: {e}")
            traceback.print_exc()  # Tambahkan ini untuk debug
            print("[!] Melewati tahap visualisasi")

    def _plot_traffic_distribution(self):
        """Plot distribusi temporal traffic."""
        try:
            # Import traceback di dalam fungsi
            import traceback
            
            # Konversi timestamp ke datetime jika belum
            if 'datetime' not in self.data.columns:
                self.data['datetime'] = pd.to_datetime(self.data['timestamp'], unit='s')
            
            # Hitung jumlah paket per detik
            packets_per_second = self.data.groupby(self.data['datetime'].dt.floor('S')).size()
            
            # Buat figure terpisah untuk setiap subplot untuk menghindari masalah dengan subplot layout
            # Plot 1: Histogram distribusi
            plt.figure(figsize=(14, 6))
            plt.hist(packets_per_second, bins=20, density=True, alpha=0.7)
            
            # Uji distribusi Poisson
            lambda_est = packets_per_second.mean()
            poisson_dist = stats.poisson(lambda_est)
            
            # Hitung histogram empiris untuk perbandingan
            hist, bin_edges = np.histogram(packets_per_second, bins=20, density=True)
            bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2
            
            # Hitung nilai PMF Poisson untuk bin_centers
            poisson_pmf = poisson_dist.pmf(np.round(bin_centers).astype(int))
            
            # Plot PMF Poisson
            plt.plot(bin_centers, poisson_pmf, 'r-', linewidth=2, label=f'Poisson PMF (λ={lambda_est:.2f})')
            
            # Uji distribusi Normal
            norm_params = stats.norm.fit(packets_per_second)
            norm_dist = stats.norm(*norm_params)
            x = np.linspace(min(packets_per_second), max(packets_per_second), 100)
            plt.plot(x, norm_dist.pdf(x), 'g-', linewidth=2, label=f'Normal PDF (μ={norm_params[0]:.2f}, σ={norm_params[1]:.2f})')
            
            plt.title('Distribusi Jumlah Paket per Detik')
            plt.xlabel('Jumlah Paket')
            plt.ylabel('Densitas')
            plt.legend()
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/traffic_distribution_hist.png", dpi=300)
            plt.close()
            
            # Plot 2: Time series
            plt.figure(figsize=(14, 6))
            # Konversi ke numpy array terlebih dahulu untuk menghindari error pandas indexing
            plt.plot(np.array(packets_per_second.index.astype(str)), np.array(packets_per_second.values))
            plt.title('Time Series Jumlah Paket per Detik')
            plt.xlabel('Waktu')
            plt.ylabel('Jumlah Paket')
            plt.grid(True)
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/traffic_distribution_time.png", dpi=300)
            plt.close()
            
            # Plot 3: Q-Q plots
            plt.figure(figsize=(12, 6))
            
            plt.subplot(1, 2, 1)
            stats.probplot(packets_per_second, dist="norm", plot=plt)
            plt.title('Q-Q Plot (Normal)')
            
            plt.subplot(1, 2, 2)
            # Untuk Poisson, kita perlu membuat Q-Q plot manual
            # Karena stats.probplot tidak mendukung Poisson secara langsung
            poisson_quantiles = poisson_dist.ppf(np.linspace(0.01, 0.99, 99))
            empirical_quantiles = np.percentile(packets_per_second, np.linspace(1, 99, 99))
            plt.scatter(poisson_quantiles, empirical_quantiles)
            plt.plot([min(poisson_quantiles), max(poisson_quantiles)], 
                    [min(poisson_quantiles), max(poisson_quantiles)], 'r--')
            plt.title('Q-Q Plot (Poisson)')
            plt.xlabel('Poisson Quantiles')
            plt.ylabel('Empirical Quantiles')
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/traffic_distribution_qq.png", dpi=300)
            plt.close()
            
            # Buat gabungan visualisasi untuk laporan
            fig = plt.figure(figsize=(14, 12))
            
            # Histogram
            plt.subplot(3, 1, 1)
            plt.hist(packets_per_second, bins=20, density=True, alpha=0.7)
            plt.plot(bin_centers, poisson_pmf, 'r-', linewidth=2, label=f'Poisson PMF (λ={lambda_est:.2f})')
            plt.plot(x, norm_dist.pdf(x), 'g-', linewidth=2, label=f'Normal PDF (μ={norm_params[0]:.2f}, σ={norm_params[1]:.2f})')
            plt.title('Distribusi Jumlah Paket per Detik')
            plt.xlabel('Jumlah Paket')
            plt.ylabel('Densitas')
            plt.legend()
            
            # Time series
            plt.subplot(3, 1, 2)
            plt.plot(np.array(packets_per_second.index.astype(str)), np.array(packets_per_second.values))
            plt.title('Time Series Jumlah Paket per Detik')
            plt.xlabel('Waktu')
            plt.ylabel('Jumlah Paket')
            plt.grid(True)
            
            # Autocorrelation - gunakan implementasi manual jika pd.plotting.autocorrelation_plot bermasalah
            plt.subplot(3, 1, 3)
            try:
                pd.plotting.autocorrelation_plot(packets_per_second)
            except Exception as e:
                print(f"    - Menggunakan implementasi manual untuk autocorrelation plot: {e}")
                from statsmodels.tsa.stattools import acf
                acf_values = acf(packets_per_second.values, nlags=40)
                plt.stem(range(len(acf_values)), acf_values)
                plt.axhline(y=0, linestyle='--', color='gray')
                plt.axhline(y=-1.96/np.sqrt(len(packets_per_second)), linestyle='--', color='gray')
                plt.axhline(y=1.96/np.sqrt(len(packets_per_second)), linestyle='--', color='gray')
            plt.title('Autocorrelation Jumlah Paket per Detik')
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/traffic_distribution.png", dpi=300)
            plt.close()
            
            return True
        except Exception as e:
            print(f"[!] Error saat membuat visualisasi distribusi traffic: {e}")
            import traceback
            traceback.print_exc()  # Tambahkan ini untuk debug
            print("[!] Melanjutkan dengan visualisasi lainnya...")
            return False

    
    def _plot_packet_type_distribution(self):
        """Plot distribusi tipe paket."""
        try:
            plt.figure(figsize=(14, 10))
            
            # Plot distribusi tipe paket
            plt.subplot(2, 2, 1)
            packet_type_counts = self.data['packet_type'].value_counts()
            plt.bar(range(len(packet_type_counts)), packet_type_counts.values)
            plt.xticks(range(len(packet_type_counts)), packet_type_counts.index, rotation=45)
            plt.title('Distribusi Tipe Paket')
            plt.xlabel('Tipe Paket')
            plt.ylabel('Jumlah Paket')
            
            # Plot distribusi tipe paket berdasarkan is_attack
            plt.subplot(2, 2, 2)
            attack_packet_types = self.data[self.data['is_attack'] == 1]['packet_type'].value_counts()
            normal_packet_types = self.data[self.data['is_attack'] == 0]['packet_type'].value_counts()
            
            # Gabungkan dan isi nilai yang hilang dengan 0
            all_types = list(set(attack_packet_types.index) | set(normal_packet_types.index))
            attack_counts = [attack_packet_types.get(t, 0) for t in all_types]
            normal_counts = [normal_packet_types.get(t, 0) for t in all_types]
            
            x = np.arange(len(all_types))
            width = 0.35
            
            plt.bar(x - width/2, normal_counts, width, label='Normal')
            plt.bar(x + width/2, attack_counts, width, label='Attack')
            plt.xticks(x, all_types, rotation=45)
            plt.title('Distribusi Tipe Paket Berdasarkan Serangan')
            plt.xlabel('Tipe Paket')
            plt.ylabel('Jumlah Paket')
            plt.legend()
            
            # Plot distribusi tipe serangan
            plt.subplot(2, 2, 3)
            attack_type_counts = self.data['attack_type'].value_counts()
            plt.bar(range(len(attack_type_counts)), attack_type_counts.values)
            plt.xticks(range(len(attack_type_counts)), attack_type_counts.index, rotation=45)
            plt.title('Distribusi Tipe Serangan')
            plt.xlabel('Tipe Serangan')
            plt.ylabel('Jumlah Paket')
            
            # Plot persentase tipe serangan
            plt.subplot(2, 2, 4)
            attack_type_percent = attack_type_counts / len(self.data) * 100
            plt.bar(range(len(attack_type_percent)), attack_type_percent.values)
            plt.xticks(range(len(attack_type_percent)), attack_type_percent.index, rotation=45)
            plt.title('Persentase Tipe Serangan dari Total Traffic')
            plt.xlabel('Tipe Serangan')
            plt.ylabel('Persentase (%)')
            plt.gca().yaxis.set_major_formatter(mtick.PercentFormatter())
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/packet_type_distribution.png", dpi=300)
            plt.close()
            return True
        except Exception as e:
            print(f"[!] Error saat membuat visualisasi distribusi tipe paket: {e}")
            return False

    def _plot_packet_size_distribution(self):
        """Plot distribusi ukuran paket."""
        try:
            plt.figure(figsize=(14, 10))
            
            # Plot histogram ukuran paket
            plt.subplot(2, 2, 1)
            plt.hist(self.data['packet_size'], bins=30, alpha=0.7)
            plt.title('Distribusi Ukuran Paket')
            plt.xlabel('Ukuran Paket (bytes)')
            plt.ylabel('Jumlah Paket')
            
            # Plot boxplot ukuran paket berdasarkan tipe paket
            plt.subplot(2, 2, 2)
            
            # Gunakan metode boxplot dari pandas yang lebih aman
            # Buat plot manual untuk setiap tipe paket
            packet_types = self.data['packet_type'].unique()
            positions = range(1, len(packet_types) + 1)
            
            box_data = []
            for pt in packet_types:
                values = self.data[self.data['packet_type'] == pt]['packet_size'].dropna().values
                box_data.append(values)
            
            # Gunakan loop untuk plot boxplot satu per satu
            for i, (pos, data, label) in enumerate(zip(positions, box_data, packet_types)):
                # Plot boxplot individual untuk setiap tipe paket
                bp = plt.boxplot(data, positions=[pos], widths=0.6, patch_artist=True)
                # Warna berbeda untuk setiap boxplot
                for patch in bp['boxes']:
                    patch.set_facecolor(f'C{i}')
            
            plt.xticks(positions, packet_types, rotation=45)
            plt.title('Ukuran Paket Berdasarkan Tipe Paket')
            plt.xlabel('Tipe Paket')
            plt.ylabel('Ukuran Paket (bytes)')
            
            # Plot boxplot ukuran paket berdasarkan tipe serangan
            plt.subplot(2, 2, 3)
            
            attack_types = self.data['attack_type'].unique()
            positions = range(1, len(attack_types) + 1)
            
            box_data = []
            for at in attack_types:
                values = self.data[self.data['attack_type'] == at]['packet_size'].dropna().values
                box_data.append(values)
            
            # Gunakan loop untuk plot boxplot satu per satu
            for i, (pos, data, label) in enumerate(zip(positions, box_data, attack_types)):
                # Plot boxplot individual untuk setiap tipe serangan
                bp = plt.boxplot(data, positions=[pos], widths=0.6, patch_artist=True)
                # Warna berbeda untuk setiap boxplot
                for patch in bp['boxes']:
                    patch.set_facecolor(f'C{i}')
            
            plt.xticks(positions, attack_types, rotation=45)
            plt.title('Ukuran Paket Berdasarkan Tipe Serangan')
            plt.xlabel('Tipe Serangan')
            plt.ylabel('Ukuran Paket (bytes)')
            
            # Plot scatter plot ukuran paket vs throughput (jika tersedia)
            plt.subplot(2, 2, 4)
            if 'throughput_kbps' in self.data.columns:
                normal_data = self.data[self.data['is_attack'] == 0]
                attack_data = self.data[self.data['is_attack'] == 1]
                plt.scatter(normal_data['packet_size'], normal_data['throughput_kbps'], alpha=0.5, label='Normal')
                plt.scatter(attack_data['packet_size'], attack_data['throughput_kbps'], alpha=0.5, label='Attack')
                plt.title('Ukuran Paket vs Throughput')
                plt.xlabel('Ukuran Paket (bytes)')
                plt.ylabel('Throughput (kbps)')
                plt.legend()
            else:
                normal_data = self.data[self.data['is_attack'] == 0]
                attack_data = self.data[self.data['is_attack'] == 1]
                plt.scatter(normal_data['packet_size'], normal_data['delay_ms'], alpha=0.5, label='Normal')
                plt.scatter(attack_data['packet_size'], attack_data['delay_ms'], alpha=0.5, label='Attack')
                plt.title('Ukuran Paket vs Delay')
                plt.xlabel('Ukuran Paket (bytes)')
                plt.ylabel('Delay (ms)')
                plt.legend()
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/packet_size_distribution.png", dpi=300)
            plt.close()
            return True
        except Exception as e:
            print(f"[!] Error saat membuat visualisasi distribusi ukuran paket: {e}")
            import traceback
            traceback.print_exc()
            return False


    def _plot_delay_distribution(self):
        """Plot distribusi delay."""
        try:
            plt.figure(figsize=(14, 10))
            
            # Plot histogram delay
            plt.subplot(2, 2, 1)
            plt.hist(self.data['delay_ms'], bins=30, density=True)
            plt.title('Distribusi Delay')
            plt.xlabel('Delay (ms)')
            plt.ylabel('Densitas')
            
            # Plot boxplot delay berdasarkan tipe node sumber
            plt.subplot(2, 2, 2)
            
            node_types = self.data['from_node_type'].unique()
            positions = range(1, len(node_types) + 1)
            
            box_data = []
            for nt in node_types:
                values = self.data[self.data['from_node_type'] == nt]['delay_ms'].dropna().values
                box_data.append(values)
            
            # Gunakan loop untuk plot boxplot satu per satu
            for i, (pos, data, label) in enumerate(zip(positions, box_data, node_types)):
                # Plot boxplot individual untuk setiap tipe node
                bp = plt.boxplot(data, positions=[pos], widths=0.6, patch_artist=True)
                # Warna berbeda untuk setiap boxplot
                for patch in bp['boxes']:
                    patch.set_facecolor(f'C{i}')
            
            plt.xticks(positions, node_types, rotation=45)
            plt.title('Delay Berdasarkan Tipe Node Sumber')
            plt.xlabel('Tipe Node Sumber')
            plt.ylabel('Delay (ms)')
            
            # Plot boxplot delay berdasarkan tipe node tujuan
            plt.subplot(2, 2, 3)
            
            node_types = self.data['to_node_type'].unique()
            positions = range(1, len(node_types) + 1)
            
            box_data = []
            for nt in node_types:
                values = self.data[self.data['to_node_type'] == nt]['delay_ms'].dropna().values
                box_data.append(values)
            
            # Gunakan loop untuk plot boxplot satu per satu
            for i, (pos, data, label) in enumerate(zip(positions, box_data, node_types)):
                # Plot boxplot individual untuk setiap tipe node
                bp = plt.boxplot(data, positions=[pos], widths=0.6, patch_artist=True)
                # Warna berbeda untuk setiap boxplot
                for patch in bp['boxes']:
                    patch.set_facecolor(f'C{i}')
            
            plt.xticks(positions, node_types, rotation=45)
            plt.title('Delay Berdasarkan Tipe Node Tujuan')
            plt.xlabel('Tipe Node Tujuan')
            plt.ylabel('Delay (ms)')
            
            # Plot scatter plot delay vs bandwidth
            plt.subplot(2, 2, 4)
            normal_data = self.data[self.data['is_attack'] == 0]
            attack_data = self.data[self.data['is_attack'] == 1]
            plt.scatter(normal_data['bandwidth_mbps'], normal_data['delay_ms'], alpha=0.5, label='Normal')
            plt.scatter(attack_data['bandwidth_mbps'], attack_data['delay_ms'], alpha=0.5, label='Attack')
            plt.title('Delay vs Bandwidth')
            plt.xlabel('Bandwidth (Mbps)')
            plt.ylabel('Delay (ms)')
            plt.legend()
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/delay_distribution.png", dpi=300)
            plt.close()
            return True
        except Exception as e:
            print(f"[!] Error saat membuat visualisasi distribusi delay: {e}")
            import traceback
            traceback.print_exc()
            return False


    def _plot_feature_correlations(self):
        """Plot korelasi antar fitur."""
        try:
            # Pilih fitur numerik
            numeric_features = ['packet_size', 'delay_ms', 'bandwidth_mbps', 'is_attack']
            if 'throughput_kbps' in self.data.columns:
                numeric_features.append('throughput_kbps')
            if 'cpu_utilization' in self.data.columns:
                numeric_features.append('cpu_utilization')
            if 'memory_utilization' in self.data.columns:
                numeric_features.append('memory_utilization')
            if 'size_ratio' in self.data.columns:
                numeric_features.append('size_ratio')
            if 'packet_rate' in self.data.columns:
                numeric_features.append('packet_rate')
            if 'is_nonexistent' in self.data.columns:
                numeric_features.append('is_nonexistent')
            
            # Hitung korelasi
            corr_matrix = self.data[numeric_features].corr()
            
            # Plot heatmap tanpa seaborn
            plt.figure(figsize=(16, 14))
            im = plt.imshow(corr_matrix, cmap='coolwarm', interpolation='nearest')
            plt.colorbar(im)
            
            # Tambahkan anotasi nilai korelasi
            for i in range(len(corr_matrix.columns)):
                for j in range(len(corr_matrix.columns)):
                    text = plt.text(j, i, f"{corr_matrix.iloc[i, j]:.2f}",
                                ha="center", va="center", color="black")
            
            # Tambahkan label
            plt.xticks(range(len(corr_matrix.columns)), corr_matrix.columns, rotation=90)
            plt.yticks(range(len(corr_matrix.columns)), corr_matrix.columns)
            
            plt.title('Korelasi antar Fitur Numerik')
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/feature_correlations.png", dpi=300)
            plt.close()
            
            # Plot korelasi dengan is_attack
            plt.figure(figsize=(12, 8))
            attack_corr = corr_matrix['is_attack'].sort_values(ascending=False)
            attack_corr = attack_corr.drop('is_attack')  # Drop self-correlation
            
            plt.barh(range(len(attack_corr)), attack_corr.values)
            plt.yticks(range(len(attack_corr)), attack_corr.index)
            plt.title('Korelasi Fitur dengan is_attack')
            plt.xlabel('Koefisien Korelasi')
            plt.ylabel('Fitur')
            plt.axvline(x=0, color='r', linestyle='--')
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/attack_correlations.png", dpi=300)
            plt.close()
            return True
        except Exception as e:
            print(f"[!] Error saat membuat visualisasi korelasi fitur: {e}")
            traceback.print_exc()  # Tambahkan ini untuk debug
            return False

    def _plot_algorithm_comparison(self):
        """Plot perbandingan performa algoritma."""
        try:
            plt.figure(figsize=(14, 10))
            
            # Kumpulkan metrik dari setiap algoritma
            algorithms = []
            accuracy = []
            precision = []
            recall = []
            f1 = []
            
            for algo in self.algorithms:
                if algo in self.models and 'metrics' in self.mitigation_stats[algo] and self.mitigation_stats[algo]['metrics']:
                    algorithms.append(algo)
                    accuracy.append(self.mitigation_stats[algo]['metrics']['accuracy'])
                    precision.append(self.mitigation_stats[algo]['metrics']['precision'])
                    recall.append(self.mitigation_stats[algo]['metrics']['recall'])
                    f1.append(self.mitigation_stats[algo]['metrics']['f1_score'])
            
            # Plot bar chart untuk setiap metrik
            x = np.arange(len(algorithms))
            width = 0.2
            
            plt.subplot(2, 2, 1)
            plt.bar(x, accuracy, width, label='Accuracy')
            plt.title('Accuracy')
            plt.xticks(x, algorithms)
            plt.ylim(0, 1)
            
            plt.subplot(2, 2, 2)
            plt.bar(x, precision, width, label='Precision')
            plt.title('Precision')
            plt.xticks(x, algorithms)
            plt.ylim(0, 1)
            
            plt.subplot(2, 2, 3)
            plt.bar(x, recall, width, label='Recall')
            plt.title('Recall')
            plt.xticks(x, algorithms)
            plt.ylim(0, 1)
            
            plt.subplot(2, 2, 4)
            plt.bar(x, f1, width, label='F1-Score')
            plt.title('F1-Score')
            plt.xticks(x, algorithms)
            plt.ylim(0, 1)
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/algorithm_comparison.png", dpi=300)
            plt.close()
            
            # Alternatif untuk radar chart tanpa menggunakan polar plot
            # Buat bar chart gabungan untuk semua metrik
            plt.figure(figsize=(12, 8))
            
            bar_width = 0.2
            index = np.arange(4)  # 4 metrik: accuracy, precision, recall, f1
            
            for i, algo in enumerate(algorithms):
                metrics = [
                    self.mitigation_stats[algo]['metrics']['accuracy'],
                    self.mitigation_stats[algo]['metrics']['precision'],
                    self.mitigation_stats[algo]['metrics']['recall'],
                    self.mitigation_stats[algo]['metrics']['f1_score']
                ]
                plt.bar(index + i * bar_width, metrics, bar_width, label=algo)
            
            plt.xlabel('Metrik')
            plt.ylabel('Nilai')
            plt.title('Perbandingan Performa Algoritma')
            plt.xticks(index + bar_width * (len(algorithms) - 1) / 2, ['Accuracy', 'Precision', 'Recall', 'F1-Score'])
            plt.legend()
            plt.ylim(0, 1.1)
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/algorithm_radar.png", dpi=300)
            plt.close()
            return True
        except Exception as e:
            print(f"[!] Error saat membuat visualisasi perbandingan algoritma: {e}")
            import traceback
            traceback.print_exc()
            return False


    def _plot_roc_curves(self):
        """Plot ROC Curve untuk setiap algoritma."""
        plt.figure(figsize=(12, 8))
        
        for algo in self.algorithms:
            if algo == 'isolation_forest':
                continue  # Skip for anomaly detection
                
            if algo in self.models and 'metrics' in self.mitigation_stats[algo] and self.mitigation_stats[algo]['metrics'] and self.mitigation_stats[algo]['metrics']['auc'] is not None:
                # Prediksi probabilitas
                y_prob = self.models[algo].predict_proba(self.X_test)[:, 1]
                
                # Hitung ROC
                fpr, tpr, _ = roc_curve(self.y_test, y_prob)
                auc_score = self.mitigation_stats[algo]['metrics']['auc']
                
                # Plot ROC curve
                plt.plot(fpr, tpr, label=f'{algo} (AUC = {auc_score:.4f})')
        
        # Plot diagonal line (random classifier)
        plt.plot([0, 1], [0, 1], 'k--', label='Random')
        
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curves')
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(f"{self.output_dir}/visualizations/roc_curves.png", dpi=300)
        plt.close()
        
        # Plot Precision-Recall curves
        plt.figure(figsize=(12, 8))
        
        for algo in self.algorithms:
            if algo == 'isolation_forest':
                continue  # Skip for anomaly detection
                
            if algo in self.models and 'metrics' in self.mitigation_stats[algo] and self.mitigation_stats[algo]['metrics'] and self.mitigation_stats[algo]['metrics']['auc'] is not None:
                # Prediksi probabilitas
                y_prob = self.models[algo].predict_proba(self.X_test)[:, 1]
                
                # Hitung Precision-Recall
                precision_vals, recall_vals, _ = precision_recall_curve(self.y_test, y_prob)
                avg_precision = average_precision_score(self.y_test, y_prob)
                
                # Plot Precision-Recall curve
                plt.plot(recall_vals, precision_vals, label=f'{algo} (AP = {avg_precision:.4f})')
        
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curves')
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(f"{self.output_dir}/visualizations/precision_recall_curves.png", dpi=300)
        plt.close()
    
    def _plot_feature_importance(self):
        """Plot feature importance untuk algoritma yang mendukung."""
        for algo in ['random_forest', 'decision_tree']:
            if algo in self.algorithms and algo in self.models and algo in self.feature_importances:
                plt.figure(figsize=(12, 8))
                
                # Ambil feature importance
                importances = self.feature_importances[algo]
                
                # Urutkan berdasarkan nilai importance
                sorted_idx = np.argsort([importances[feature] for feature in self.feature_columns])
                
                # Plot bar chart
                plt.barh(range(len(sorted_idx)), 
                         [importances[self.feature_columns[i]] for i in sorted_idx],
                         align='center')
                plt.yticks(range(len(sorted_idx)), [self.feature_columns[i] for i in sorted_idx])
                plt.title(f'Feature Importance - {algo.upper()}')
                plt.xlabel('Importance')
                plt.tight_layout()
                plt.savefig(f"{self.output_dir}/visualizations/{algo}/feature_importance.png", dpi=300)
                plt.close()
    
    def _plot_confusion_matrices(self):
        """Plot confusion matrix untuk setiap algoritma."""
        for algo in self.algorithms:
            if algo in self.models and 'metrics' in self.mitigation_stats[algo] and self.mitigation_stats[algo]['metrics'] and 'confusion_matrix' in self.mitigation_stats[algo]['metrics']:
                plt.figure(figsize=(10, 8))
                
                cm = self.mitigation_stats[algo]['metrics']['confusion_matrix']
                
                # Plot confusion matrix
                sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                           xticklabels=['Normal', 'Attack'],
                           yticklabels=['Normal', 'Attack'])
                
                plt.title(f'Confusion Matrix - {algo.upper()}')
                plt.ylabel('True Label')
                plt.xlabel('Predicted Label')
                plt.tight_layout()
                plt.savefig(f"{self.output_dir}/visualizations/{algo}/confusion_matrix.png", dpi=300)
                plt.close()
    
    def _plot_mitigation_comparison(self):
        """Plot perbandingan sebelum dan sesudah mitigasi untuk setiap algoritma."""
        plt.figure(figsize=(16, 12))
        
        # Data untuk plot
        categories = ['Total Packets', 'Attack Packets', 'Legitimate Packets']
        
        # Jumlah algoritma dan kategori
        n_algorithms = len([algo for algo in self.algorithms if algo in self.models])
        n_categories = len(categories)
        
        # Posisi bar
        x = np.arange(n_categories)
        width = 0.8 / (n_algorithms + 1)  # +1 untuk 'Before'
        
        # Plot 'Before' bars
        before_values = [
            self.mitigation_stats[self.algorithms[0]]['total_packets']['before'],
            self.mitigation_stats[self.algorithms[0]]['attack_packets']['before'],
            self.mitigation_stats[self.algorithms[0]]['legitimate_packets']['before']
        ]
        plt.bar(x - 0.4 + width/2, before_values, width, label='Before Mitigation')
        
        # Plot bars untuk setiap algoritma
        algo_idx = 0
        for algo in self.algorithms:
            if algo in self.models:
                after_values = [
                    self.mitigation_stats[algo]['total_packets']['after'],
                    self.mitigation_stats[algo]['attack_packets']['after'],
                    self.mitigation_stats[algo]['legitimate_packets']['after']
                ]
                plt.bar(x - 0.4 + (algo_idx + 1.5) * width, after_values, width, label=f'After {algo.upper()}')
                algo_idx += 1
        
        # Tambahkan label dan legenda
        plt.xlabel('Kategori Paket')
        plt.ylabel('Jumlah Paket')
        plt.title('Perbandingan Sebelum dan Sesudah Mitigasi')
        plt.xticks(x, categories)
        plt.legend()
        
        # Tambahkan nilai di atas bar
        for i, v in enumerate(before_values):
            plt.text(i - 0.4 + width/2, v + 5, str(v), ha='center', va='bottom', fontsize=9)
        
        algo_idx = 0
        for algo in self.algorithms:
            if algo in self.models:
                after_values = [
                    self.mitigation_stats[algo]['total_packets']['after'],
                    self.mitigation_stats[algo]['attack_packets']['after'],
                    self.mitigation_stats[algo]['legitimate_packets']['after']
                ]
                for j, v in enumerate(after_values):
                    plt.text(j - 0.4 + (algo_idx + 1.5) * width, v + 5, str(v), ha='center', va='bottom', fontsize=9)
                algo_idx += 1
        
        plt.tight_layout()
        plt.savefig(f"{self.output_dir}/visualizations/mitigation_comparison.png", dpi=300)
        plt.close()
        
        # Plot persentase pengurangan
        plt.figure(figsize=(14, 8))
        
        # Data untuk plot
        reduction_data = []
        algo_labels = []
        for algo in self.algorithms:
            if algo in self.models:
                reduction_data.append([
                    self.mitigation_stats[algo]['total_packets']['reduction'],
                    self.mitigation_stats[algo]['attack_packets']['reduction'],
                    self.mitigation_stats[algo]['legitimate_packets']['reduction']
                ])
                algo_labels.append(algo)
        
        # Plot bar chart
        x = np.arange(n_categories)
        width = 0.8 / len(algo_labels) if len(algo_labels) > 0 else 0.4
        
        for i, algo in enumerate(algo_labels):
            plt.bar(x - 0.4 + (i + 0.5) * width, reduction_data[i], width, label=algo.upper())
        
        # Tambahkan label dan legenda
        plt.xlabel('Kategori Paket')
        plt.ylabel('Persentase Pengurangan (%)')
        plt.title('Persentase Pengurangan Paket Setelah Mitigasi')
        plt.xticks(x, categories)
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Tambahkan nilai di atas bar
        for i, algo in enumerate(algo_labels):
            for j, v in enumerate(reduction_data[i]):
                plt.text(j - 0.4 + (i + 0.5) * width, v + 0.5, f"{v:.1f}%", ha='center', va='bottom', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(f"{self.output_dir}/visualizations/reduction_comparison.png", dpi=300)
        plt.close()
    
    def _plot_traffic_distribution(self):
        """Plot distribusi temporal traffic."""
        try:
            # Import traceback di dalam fungsi
            import traceback
            
            # Konversi timestamp ke datetime jika belum
            if 'datetime' not in self.data.columns:
                self.data['datetime'] = pd.to_datetime(self.data['timestamp'], unit='s')
            
            # Hitung jumlah paket per detik
            packets_per_second = self.data.groupby(self.data['datetime'].dt.floor('S')).size()
            
            # Buat figure terpisah untuk setiap subplot untuk menghindari masalah dengan subplot layout
            # Plot 1: Histogram distribusi
            plt.figure(figsize=(14, 6))
            plt.hist(packets_per_second, bins=20, density=True, alpha=0.7)
            
            # Uji distribusi Poisson
            lambda_est = packets_per_second.mean()
            poisson_dist = stats.poisson(lambda_est)
            
            # Hitung histogram empiris untuk perbandingan
            hist, bin_edges = np.histogram(packets_per_second, bins=20, density=True)
            bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2
            
            # Hitung nilai PMF Poisson untuk bin_centers
            poisson_pmf = poisson_dist.pmf(np.round(bin_centers).astype(int))
            
            # Plot PMF Poisson
            plt.plot(bin_centers, poisson_pmf, 'r-', linewidth=2, label=f'Poisson PMF (λ={lambda_est:.2f})')
            
            # Uji distribusi Normal
            norm_params = stats.norm.fit(packets_per_second)
            norm_dist = stats.norm(*norm_params)
            x = np.linspace(min(packets_per_second), max(packets_per_second), 100)
            plt.plot(x, norm_dist.pdf(x), 'g-', linewidth=2, label=f'Normal PDF (μ={norm_params[0]:.2f}, σ={norm_params[1]:.2f})')
            
            plt.title('Distribusi Jumlah Paket per Detik')
            plt.xlabel('Jumlah Paket')
            plt.ylabel('Densitas')
            plt.legend()
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/traffic_distribution_hist.png", dpi=300)
            plt.close()
            
            # Plot 2: Time series
            plt.figure(figsize=(14, 6))
            # Konversi ke numpy array terlebih dahulu untuk menghindari error pandas indexing
            plt.plot(np.array(packets_per_second.index.astype(str)), np.array(packets_per_second.values))
            plt.title('Time Series Jumlah Paket per Detik')
            plt.xlabel('Waktu')
            plt.ylabel('Jumlah Paket')
            plt.grid(True)
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/traffic_distribution_time.png", dpi=300)
            plt.close()
            
            # Plot 3: Q-Q plots
            plt.figure(figsize=(12, 6))
            
            plt.subplot(1, 2, 1)
            stats.probplot(packets_per_second, dist="norm", plot=plt)
            plt.title('Q-Q Plot (Normal)')
            
            plt.subplot(1, 2, 2)
            # Untuk Poisson, kita perlu membuat Q-Q plot manual
            # Karena stats.probplot tidak mendukung Poisson secara langsung
            poisson_quantiles = poisson_dist.ppf(np.linspace(0.01, 0.99, 99))
            empirical_quantiles = np.percentile(packets_per_second, np.linspace(1, 99, 99))
            plt.scatter(poisson_quantiles, empirical_quantiles)
            plt.plot([min(poisson_quantiles), max(poisson_quantiles)], 
                    [min(poisson_quantiles), max(poisson_quantiles)], 'r--')
            plt.title('Q-Q Plot (Poisson)')
            plt.xlabel('Poisson Quantiles')
            plt.ylabel('Empirical Quantiles')
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/traffic_distribution_qq.png", dpi=300)
            plt.close()
            
            # Buat gabungan visualisasi untuk laporan
            fig = plt.figure(figsize=(14, 12))
            
            # Histogram
            plt.subplot(3, 1, 1)
            plt.hist(packets_per_second, bins=20, density=True, alpha=0.7)
            plt.plot(bin_centers, poisson_pmf, 'r-', linewidth=2, label=f'Poisson PMF (λ={lambda_est:.2f})')
            plt.plot(x, norm_dist.pdf(x), 'g-', linewidth=2, label=f'Normal PDF (μ={norm_params[0]:.2f}, σ={norm_params[1]:.2f})')
            plt.title('Distribusi Jumlah Paket per Detik')
            plt.xlabel('Jumlah Paket')
            plt.ylabel('Densitas')
            plt.legend()
            
            # Time series
            plt.subplot(3, 1, 2)
            plt.plot(np.array(packets_per_second.index.astype(str)), np.array(packets_per_second.values))
            plt.title('Time Series Jumlah Paket per Detik')
            plt.xlabel('Waktu')
            plt.ylabel('Jumlah Paket')
            plt.grid(True)
            
            # Autocorrelation - gunakan implementasi manual jika pd.plotting.autocorrelation_plot bermasalah
            plt.subplot(3, 1, 3)
            try:
                pd.plotting.autocorrelation_plot(packets_per_second)
            except Exception as e:
                print(f"    - Menggunakan implementasi manual untuk autocorrelation plot: {e}")
                from statsmodels.tsa.stattools import acf
                acf_values = acf(packets_per_second.values, nlags=40)
                plt.stem(range(len(acf_values)), acf_values)
                plt.axhline(y=0, linestyle='--', color='gray')
                plt.axhline(y=-1.96/np.sqrt(len(packets_per_second)), linestyle='--', color='gray')
                plt.axhline(y=1.96/np.sqrt(len(packets_per_second)), linestyle='--', color='gray')
            plt.title('Autocorrelation Jumlah Paket per Detik')
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/traffic_distribution.png", dpi=300)
            plt.close()
            
            return True
        except Exception as e:
            print(f"[!] Error saat membuat visualisasi distribusi traffic: {e}")
            import traceback
            traceback.print_exc()  # Tambahkan ini untuk debug
            print("[!] Melanjutkan dengan visualisasi lainnya...")
            return False

    def _plot_packet_size_distribution(self):
        """Plot distribusi ukuran paket."""
        try:
            plt.figure(figsize=(14, 10))
            
            # Plot histogram ukuran paket
            plt.subplot(2, 2, 1)
            plt.hist(self.data['packet_size'], bins=30, alpha=0.7)
            plt.title('Distribusi Ukuran Paket')
            plt.xlabel('Ukuran Paket (bytes)')
            plt.ylabel('Jumlah Paket')
            
            # Plot boxplot ukuran paket berdasarkan tipe paket
            plt.subplot(2, 2, 2)
            
            # Gunakan metode boxplot dari pandas yang lebih aman
            # Buat plot manual untuk setiap tipe paket
            packet_types = self.data['packet_type'].unique()
            positions = range(1, len(packet_types) + 1)
            
            box_data = []
            for pt in packet_types:
                values = self.data[self.data['packet_type'] == pt]['packet_size'].dropna().values
                box_data.append(values)
            
            # Gunakan loop untuk plot boxplot satu per satu
            for i, (pos, data, label) in enumerate(zip(positions, box_data, packet_types)):
                # Plot boxplot individual untuk setiap tipe paket
                bp = plt.boxplot(data, positions=[pos], widths=0.6, patch_artist=True)
                # Warna berbeda untuk setiap boxplot
                for patch in bp['boxes']:
                    patch.set_facecolor(f'C{i}')
            
            plt.xticks(positions, packet_types, rotation=45)
            plt.title('Ukuran Paket Berdasarkan Tipe Paket')
            plt.xlabel('Tipe Paket')
            plt.ylabel('Ukuran Paket (bytes)')
            
            # Plot boxplot ukuran paket berdasarkan tipe serangan
            plt.subplot(2, 2, 3)
            
            attack_types = self.data['attack_type'].unique()
            positions = range(1, len(attack_types) + 1)
            
            box_data = []
            for at in attack_types:
                values = self.data[self.data['attack_type'] == at]['packet_size'].dropna().values
                box_data.append(values)
            
            # Gunakan loop untuk plot boxplot satu per satu
            for i, (pos, data, label) in enumerate(zip(positions, box_data, attack_types)):
                # Plot boxplot individual untuk setiap tipe serangan
                bp = plt.boxplot(data, positions=[pos], widths=0.6, patch_artist=True)
                # Warna berbeda untuk setiap boxplot
                for patch in bp['boxes']:
                    patch.set_facecolor(f'C{i}')
            
            plt.xticks(positions, attack_types, rotation=45)
            plt.title('Ukuran Paket Berdasarkan Tipe Serangan')
            plt.xlabel('Tipe Serangan')
            plt.ylabel('Ukuran Paket (bytes)')
            
            # Plot scatter plot ukuran paket vs throughput (jika tersedia)
            plt.subplot(2, 2, 4)
            if 'throughput_kbps' in self.data.columns:
                normal_data = self.data[self.data['is_attack'] == 0]
                attack_data = self.data[self.data['is_attack'] == 1]
                plt.scatter(normal_data['packet_size'], normal_data['throughput_kbps'], alpha=0.5, label='Normal')
                plt.scatter(attack_data['packet_size'], attack_data['throughput_kbps'], alpha=0.5, label='Attack')
                plt.title('Ukuran Paket vs Throughput')
                plt.xlabel('Ukuran Paket (bytes)')
                plt.ylabel('Throughput (kbps)')
                plt.legend()
            else:
                normal_data = self.data[self.data['is_attack'] == 0]
                attack_data = self.data[self.data['is_attack'] == 1]
                plt.scatter(normal_data['packet_size'], normal_data['delay_ms'], alpha=0.5, label='Normal')
                plt.scatter(attack_data['packet_size'], attack_data['delay_ms'], alpha=0.5, label='Attack')
                plt.title('Ukuran Paket vs Delay')
                plt.xlabel('Ukuran Paket (bytes)')
                plt.ylabel('Delay (ms)')
                plt.legend()
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/packet_size_distribution.png", dpi=300)
            plt.close()
            return True
        except Exception as e:
            print(f"[!] Error saat membuat visualisasi distribusi ukuran paket: {e}")
            import traceback
            traceback.print_exc()
            return False


    def _plot_delay_distribution(self):
        """Plot distribusi delay."""
        try:
            plt.figure(figsize=(14, 10))
            
            # Plot histogram delay
            plt.subplot(2, 2, 1)
            plt.hist(self.data['delay_ms'], bins=30, density=True)
            plt.title('Distribusi Delay')
            plt.xlabel('Delay (ms)')
            plt.ylabel('Densitas')
            
            # Plot boxplot delay berdasarkan tipe node sumber
            plt.subplot(2, 2, 2)
            
            node_types = self.data['from_node_type'].unique()
            positions = range(1, len(node_types) + 1)
            
            box_data = []
            for nt in node_types:
                values = self.data[self.data['from_node_type'] == nt]['delay_ms'].dropna().values
                box_data.append(values)
            
            # Gunakan loop untuk plot boxplot satu per satu
            for i, (pos, data, label) in enumerate(zip(positions, box_data, node_types)):
                # Plot boxplot individual untuk setiap tipe node
                bp = plt.boxplot(data, positions=[pos], widths=0.6, patch_artist=True)
                # Warna berbeda untuk setiap boxplot
                for patch in bp['boxes']:
                    patch.set_facecolor(f'C{i}')
            
            plt.xticks(positions, node_types, rotation=45)
            plt.title('Delay Berdasarkan Tipe Node Sumber')
            plt.xlabel('Tipe Node Sumber')
            plt.ylabel('Delay (ms)')
            
            # Plot boxplot delay berdasarkan tipe node tujuan
            plt.subplot(2, 2, 3)
            
            node_types = self.data['to_node_type'].unique()
            positions = range(1, len(node_types) + 1)
            
            box_data = []
            for nt in node_types:
                values = self.data[self.data['to_node_type'] == nt]['delay_ms'].dropna().values
                box_data.append(values)
            
            # Gunakan loop untuk plot boxplot satu per satu
            for i, (pos, data, label) in enumerate(zip(positions, box_data, node_types)):
                # Plot boxplot individual untuk setiap tipe node
                bp = plt.boxplot(data, positions=[pos], widths=0.6, patch_artist=True)
                # Warna berbeda untuk setiap boxplot
                for patch in bp['boxes']:
                    patch.set_facecolor(f'C{i}')
            
            plt.xticks(positions, node_types, rotation=45)
            plt.title('Delay Berdasarkan Tipe Node Tujuan')
            plt.xlabel('Tipe Node Tujuan')
            plt.ylabel('Delay (ms)')
            
            # Plot scatter plot delay vs bandwidth
            plt.subplot(2, 2, 4)
            normal_data = self.data[self.data['is_attack'] == 0]
            attack_data = self.data[self.data['is_attack'] == 1]
            plt.scatter(normal_data['bandwidth_mbps'], normal_data['delay_ms'], alpha=0.5, label='Normal')
            plt.scatter(attack_data['bandwidth_mbps'], attack_data['delay_ms'], alpha=0.5, label='Attack')
            plt.title('Delay vs Bandwidth')
            plt.xlabel('Bandwidth (Mbps)')
            plt.ylabel('Delay (ms)')
            plt.legend()
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/delay_distribution.png", dpi=300)
            plt.close()
            return True
        except Exception as e:
            print(f"[!] Error saat membuat visualisasi distribusi delay: {e}")
            import traceback
            traceback.print_exc()
            return False



    def _plot_algorithm_comparison(self):
        """Plot perbandingan performa algoritma."""
        try:
            plt.figure(figsize=(14, 10))
            
            # Kumpulkan metrik dari setiap algoritma
            algorithms = []
            accuracy = []
            precision = []
            recall = []
            f1 = []
            
            for algo in self.algorithms:
                if algo in self.models and 'metrics' in self.mitigation_stats[algo] and self.mitigation_stats[algo]['metrics']:
                    algorithms.append(algo)
                    accuracy.append(self.mitigation_stats[algo]['metrics']['accuracy'])
                    precision.append(self.mitigation_stats[algo]['metrics']['precision'])
                    recall.append(self.mitigation_stats[algo]['metrics']['recall'])
                    f1.append(self.mitigation_stats[algo]['metrics']['f1_score'])
            
            # Plot bar chart untuk setiap metrik
            x = np.arange(len(algorithms))
            width = 0.2
            
            plt.subplot(2, 2, 1)
            plt.bar(x, accuracy, width, label='Accuracy')
            plt.title('Accuracy')
            plt.xticks(x, algorithms)
            plt.ylim(0, 1)
            
            plt.subplot(2, 2, 2)
            plt.bar(x, precision, width, label='Precision')
            plt.title('Precision')
            plt.xticks(x, algorithms)
            plt.ylim(0, 1)
            
            plt.subplot(2, 2, 3)
            plt.bar(x, recall, width, label='Recall')
            plt.title('Recall')
            plt.xticks(x, algorithms)
            plt.ylim(0, 1)
            
            plt.subplot(2, 2, 4)
            plt.bar(x, f1, width, label='F1-Score')
            plt.title('F1-Score')
            plt.xticks(x, algorithms)
            plt.ylim(0, 1)
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/algorithm_comparison.png", dpi=300)
            plt.close()
            
            # Alternatif untuk radar chart tanpa menggunakan polar plot
            # Buat bar chart gabungan untuk semua metrik
            plt.figure(figsize=(12, 8))
            
            bar_width = 0.2
            index = np.arange(4)  # 4 metrik: accuracy, precision, recall, f1
            
            for i, algo in enumerate(algorithms):
                metrics = [
                    self.mitigation_stats[algo]['metrics']['accuracy'],
                    self.mitigation_stats[algo]['metrics']['precision'],
                    self.mitigation_stats[algo]['metrics']['recall'],
                    self.mitigation_stats[algo]['metrics']['f1_score']
                ]
                plt.bar(index + i * bar_width, metrics, bar_width, label=algo)
            
            plt.xlabel('Metrik')
            plt.ylabel('Nilai')
            plt.title('Perbandingan Performa Algoritma')
            plt.xticks(index + bar_width * (len(algorithms) - 1) / 2, ['Accuracy', 'Precision', 'Recall', 'F1-Score'])
            plt.legend()
            plt.ylim(0, 1.1)
            
            plt.tight_layout()
            plt.savefig(f"{self.output_dir}/visualizations/algorithm_radar.png", dpi=300)
            plt.close()
            return True
        except Exception as e:
            print(f"[!] Error saat membuat visualisasi perbandingan algoritma: {e}")
            import traceback
            traceback.print_exc()
            return False



    ## 5. Perbaikan untuk `generate_summary_report`:

    def generate_summary_report(self):
        """Buat laporan ringkasan hasil mitigasi."""
        print(SECTION_HEADER("Laporan Ringkasan"))
        
        try:
            # Import yang diperlukan
            from scipy import stats
            
            # Buat direktori output jika belum ada
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
            
            # Buat laporan dalam format Markdown
            report_path = f"{self.output_dir}/summary_report.md"
            with open(report_path, 'w') as f:
                f.write('# Laporan Ringkasan Mitigasi Jaringan NDN\n\n')
                f.write(f'*Dibuat pada: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*\n\n')
                
                f.write('## Hasil Deteksi Serangan\n\n')
                
                f.write('### Interest Flooding\n')
                f.write(f"- Paket terdeteksi: {self.attack_stats['interest_flooding']['packet_count']}\n")
                f.write(f"- Node mencurigakan: {', '.join(self.attack_stats['interest_flooding']['nodes'])}\n")
                f.write(f"- Persentase traffic: {self.attack_stats['interest_flooding']['percent_of_traffic']:.2f}%\n\n")
                
                f.write('### Cache Poisoning\n')
                f.write(f"- Paket terdeteksi: {self.attack_stats['cache_poisoning']['packet_count']}\n")
                f.write(f"- Node mencurigakan: {', '.join(self.attack_stats['cache_poisoning']['nodes'])}\n")
                f.write(f"- Persentase traffic: {self.attack_stats['cache_poisoning']['percent_of_traffic']:.2f}%\n\n")
                
                f.write('## Analisis Distribusi Traffic\n\n')
                f.write('Hasil analisis menunjukkan bahwa distribusi temporal traffic memiliki karakteristik sebagai berikut:\n\n')
                
                # Analisis distribusi temporal
                if 'datetime' not in self.data.columns:
                    self.data['datetime'] = pd.to_datetime(self.data['timestamp'], unit='s')
                    
                packets_per_second = self.data.groupby(self.data['datetime'].dt.floor('S')).size()
                lambda_est = packets_per_second.mean()
                poisson_dist = stats.poisson(lambda_est)
                ks_stat, ks_pvalue = stats.kstest(packets_per_second, poisson_dist.cdf)
                
                f.write(f"- Rata-rata paket per detik: {lambda_est:.2f}\n")
                f.write(f"- Uji Kolmogorov-Smirnov untuk distribusi Poisson: stat={ks_stat:.4f}, p-value={ks_pvalue:.4f}\n")
                
                if ks_pvalue < 0.05:
                    f.write("- Distribusi temporal **TIDAK** mengikuti distribusi Poisson (p < 0.05)\n\n")
                    
                    # Coba distribusi lain
                    norm_params = stats.norm.fit(packets_per_second)
                    norm_dist = stats.norm(*norm_params)
                    ks_stat_norm, ks_pvalue_norm = stats.kstest(packets_per_second, norm_dist.cdf)
                    
                    exp_params = stats.expon.fit(packets_per_second)
                    exp_dist = stats.expon(*exp_params)
                    ks_stat_exp, ks_pvalue_exp = stats.kstest(packets_per_second, exp_dist.cdf)
                    
                    f.write(f"- Uji distribusi Normal: stat={ks_stat_norm:.4f}, p-value={ks_pvalue_norm:.4f}\n")
                    f.write(f"- Uji distribusi Exponential: stat={ks_stat_exp:.4f}, p-value={ks_pvalue_exp:.4f}\n\n")
                    
                    # Tentukan distribusi terbaik
                    distributions = {
                        'Poisson': ks_pvalue,
                        'Normal': ks_pvalue_norm,
                        'Exponential': ks_pvalue_exp
                    }
                    best_dist = max(distributions.items(), key=lambda x: x[1])
                    f.write(f"- Distribusi terbaik: **{best_dist[0]}** (p-value={best_dist[1]:.4f})\n\n")
                else:
                    f.write("- Distribusi temporal mengikuti distribusi **Poisson** (p >= 0.05)\n\n")
                
                f.write('## Perbandingan Algoritma Machine Learning\n\n')
                
                # Tabel perbandingan metrik
                f.write('### Metrik Evaluasi\n\n')
                f.write('| Algoritma | Accuracy | Precision | Recall | F1-Score | AUC |\n')
                f.write('|-----------|----------|-----------|--------|----------|-----|\n')
                
                for algo in self.algorithms:
                    if algo in self.models and 'metrics' in self.mitigation_stats[algo] and self.mitigation_stats[algo]['metrics']:
                        metrics = self.mitigation_stats[algo]['metrics']
                        auc_value = metrics['auc'] if metrics['auc'] is not None else 'N/A'
                        f.write(f"| {algo.upper()} | {metrics['accuracy']:.4f} | {metrics['precision']:.4f} | {metrics['recall']:.4f} | {metrics['f1_score']:.4f} | {auc_value if isinstance(auc_value, str) else f'{auc_value:.4f}'} |\n")
                
                f.write('\n### Hasil Mitigasi\n\n')
                f.write('| Algoritma | Total Packets (Before) | Total Packets (After) | Reduction | Attack Packets (Before) | Attack Packets (After) | Reduction | Legitimate Packets (Before) | Legitimate Packets (After) | Reduction |\n')
                f.write('|-----------|------------------------|----------------------|-----------|-------------------------|------------------------|-----------|------------------------------|----------------------------|----------|\n')
                
                for algo in self.algorithms:
                    if algo in self.models:
                        stats = self.mitigation_stats[algo]
                        f.write(f"| {algo.upper()} | {stats['total_packets']['before']} | {stats['total_packets']['after']} | {stats['total_packets']['reduction']:.2f}% | {stats['attack_packets']['before']} | {stats['attack_packets']['after']} | {stats['attack_packets']['reduction']:.2f}% | {stats['legitimate_packets']['before']} | {stats['legitimate_packets']['after']} | {stats['legitimate_packets']['reduction']:.2f}% |\n")
                
                f.write('\n## Feature Importance\n\n')
                for algo in ['random_forest', 'decision_tree']:
                    if algo in self.algorithms and algo in self.models and algo in self.feature_importances:
                        f.write(f'### {algo.upper()}\n\n')
                        
                        # Sort features by importance
                        sorted_features = sorted(self.feature_importances[algo].items(), key=lambda x: x[1], reverse=True)
                        
                        f.write('| Feature | Importance |\n')
                        f.write('|---------|------------|\n')
                        for feature, importance in sorted_features:
                            f.write(f"| {feature} | {importance:.4f} |\n")
                        f.write('\n')
                
                f.write('## Visualisasi\n\n')
                f.write('Visualisasi hasil analisis dan mitigasi tersedia dalam direktori output:\n\n')
                f.write('1. **traffic_distribution.png** - Distribusi temporal traffic\n')
                f.write('2. **packet_type_distribution.png** - Distribusi tipe paket\n')
                f.write('3. **packet_size_distribution.png** - Distribusi ukuran paket\n')
                f.write('4. **delay_distribution.png** - Distribusi delay\n')
                f.write('5. **feature_correlations.png** - Korelasi antar fitur\n')
                f.write('6. **attack_correlations.png** - Korelasi fitur dengan serangan\n')
                f.write('7. **algorithm_comparison.png** - Perbandingan performa algoritma\n')
                f.write('8. **algorithm_radar.png** - Radar chart perbandingan algoritma\n')
                f.write('9. **roc_curves.png** - ROC Curves\n')
                f.write('10. **precision_recall_curves.png** - Precision-Recall Curves\n')
                f.write('11. **mitigation_comparison.png** - Perbandingan hasil mitigasi\n')
                f.write('12. **reduction_comparison.png** - Perbandingan persentase pengurangan\n\n')
                
                f.write('Untuk setiap algoritma, tersedia visualisasi tambahan di subdirektori masing-masing:\n\n')
                for algo in self.algorithms:
                    if algo in self.models:
                                    f.write('Untuk setiap algoritma, tersedia visualisasi tambahan di subdirektori masing-masing:\n\n')
                for algo in self.algorithms:
                    if algo in self.models:
                        f.write(f'### {algo.upper()}\n\n')
                        f.write(f'1. **{algo}/confusion_matrix.png** - Confusion Matrix\n')
                        if algo in ['random_forest', 'decision_tree']:
                            f.write(f'2. **{algo}/feature_importance.png** - Feature Importance\n')
                        f.write('\n')
                
                # Tambahkan rekomendasi mitigasi
                f.write('## Rekomendasi Mitigasi\n\n')
                
                # Rekomendasi untuk Interest Flooding
                f.write('### Mitigasi Interest Flooding Attack\n\n')
                f.write('Berdasarkan analisis, berikut rekomendasi untuk mitigasi Interest Flooding Attack:\n\n')
                f.write('1. **Rate Limiting**: Terapkan pembatasan rate untuk Interest Packets dari node-node mencurigakan.\n')
                f.write('2. **Prefix Filtering**: Filter Interest Packets dengan prefix yang tidak valid atau mencurigakan.\n')
                f.write('3. **Satisfaction-based Pushback**: Kurangi batas rate untuk node yang memiliki rasio kepuasan Interest yang rendah.\n')
                f.write('4. **Collaborative Mitigation**: Bagikan informasi tentang node mencurigakan antar router NDN.\n')
                
                # Rekomendasi untuk Cache Poisoning
                f.write('\n### Mitigasi Cache Poisoning Attack\n\n')
                f.write('Untuk mengatasi Cache Poisoning Attack, rekomendasi berikut dapat diterapkan:\n\n')
                f.write('1. **Content Verification**: Verifikasi keaslian konten dengan tanda tangan kriptografis.\n')
                f.write('2. **Cache Partitioning**: Pisahkan cache untuk konten yang terverifikasi dan yang belum terverifikasi.\n')
                f.write('3. **Freshness Control**: Atur waktu kedaluwarsa konten dalam cache untuk membatasi dampak konten yang tercemar.\n')
                f.write('4. **Trust Management**: Implementasikan sistem manajemen kepercayaan untuk mengevaluasi sumber konten.\n')
                
                # Rekomendasi umum
                f.write('\n### Rekomendasi Umum\n\n')
                f.write('1. **Monitoring Berkelanjutan**: Terapkan sistem monitoring real-time untuk mendeteksi anomali traffic.\n')
                f.write('2. **Update Model ML**: Perbarui model ML secara berkala dengan data terbaru untuk meningkatkan akurasi deteksi.\n')
                f.write('3. **Penggunaan Ensemble Methods**: Kombinasikan hasil dari beberapa algoritma ML untuk keputusan mitigasi yang lebih robust.\n')
                f.write('4. **Validasi Cross-Domain**: Validasi deteksi serangan dengan informasi dari domain lain (mis. sistem IDS tradisional).\n')
                
                # Algoritma terbaik
                best_algo_metrics = [(algo, stats['metrics']['f1_score']) for algo, stats in self.mitigation_stats.items() 
                                if algo in self.models and 'metrics' in stats and 'f1_score' in stats['metrics']]
                
                if best_algo_metrics:
                    best_algo = max(best_algo_metrics, key=lambda x: x[1])[0]
                    
                    f.write(f'\n### Algoritma Terbaik\n\n')
                    f.write(f'Berdasarkan evaluasi, **{best_algo.upper()}** menunjukkan performa terbaik dengan F1-Score {self.mitigation_stats[best_algo]["metrics"]["f1_score"]:.4f}.\n')
                    f.write(f'Algoritma ini direkomendasikan untuk implementasi dalam sistem mitigasi produksi.\n\n')
                
                # Kesimpulan
                f.write('## Kesimpulan\n\n')
                f.write('Analisis menunjukkan bahwa serangan terhadap jaringan NDN dapat dideteksi dan dimitigasi secara efektif menggunakan pendekatan machine learning. ')
                f.write('Dengan menerapkan strategi mitigasi yang tepat, dampak serangan dapat dikurangi secara signifikan sambil meminimalkan pengaruh terhadap traffic legitimate.\n\n')
                f.write('Sistem mitigasi ini dapat diintegrasikan ke dalam infrastruktur NDN untuk meningkatkan keamanan dan keandalan jaringan.')
            
            print(f"[+] Laporan ringkasan disimpan di {report_path}")
            return True
        except Exception as e:
            print(f"[!] Error saat membuat laporan ringkasan: {e}")
            import traceback
            traceback.print_exc()
            return False

        
    def export_mitigation_config(self):
        """Ekspor konfigurasi mitigasi yang digunakan."""
        config_path = f"{self.output_dir}/mitigation_config.json"
        
        # Buat dictionary konfigurasi
        config = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'dataset': self.dataset_path,
            'algorithms': self.algorithms,
            'ml_params': self.ml_params,
            'suspicious_nodes': {
                'interest_flooding': list(self.attack_stats['interest_flooding']['nodes']),
                'cache_poisoning': list(self.attack_stats['cache_poisoning']['nodes'])
            },
            'feature_columns': self.feature_columns,
            'mitigation_stats': {
                algo: {
                    'total_packets': self.mitigation_stats[algo]['total_packets'],
                    'attack_packets': self.mitigation_stats[algo]['attack_packets'],
                    'legitimate_packets': self.mitigation_stats[algo]['legitimate_packets']
                } for algo in self.algorithms if algo in self.models
            }
        }
        
        # Simpan ke file JSON
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        
        print(f"[+] Konfigurasi mitigasi disimpan di {config_path}")

# ==============================
# SECTION: Fungsi Utama
# ==============================

def main():
    """Fungsi utama untuk menjalankan sistem mitigasi NDN."""
    # Tampilkan header
    print(NDN_HEADER)
    print(VERSION_INFO)
    
    # Parse argumen command line
    parser = argparse.ArgumentParser(description='Sistem Mitigasi Serangan NDN dengan Multiple ML Algorithms')
    parser.add_argument('--dataset', type=str, required=True, help='Path ke file dataset CSV')
    parser.add_argument('--output', type=str, default='mitigation_results_final', help='Direktori untuk menyimpan hasil mitigasi')
    parser.add_argument('--algorithms', type=str, nargs='+', 
                        default=['random_forest', 'decision_tree', 'knn', 'isolation_forest', 'hist_gradient_boosting'], 
                        help='Algoritma ML yang akan digunakan (random_forest, decision_tree, knn, isolation_forest, hist_gradient_boosting)')
    parser.add_argument('--visualize', action='store_true', help='Buat visualisasi hasil')
    parser.add_argument('--report', action='store_true', help='Buat laporan ringkasan')
    parser.add_argument('--analyze-only', action='store_true', help='Hanya analisis dataset tanpa mitigasi')
    parser.add_argument('--full', action='store_true', help='Jalankan semua tahap (analisis, mitigasi, visualisasi, laporan)')
    args = parser.parse_args()
    
    # Jika opsi full digunakan, aktifkan semua opsi
    if args.full:
        args.visualize = True
        args.report = True
    
    # Validasi file dataset
    if not os.path.exists(args.dataset):
        print(f"[!] Error: File dataset '{args.dataset}' tidak ditemukan.")
        return 1
    
    # Validasi algoritma
    valid_algorithms = ['random_forest', 'decision_tree', 'knn', 'isolation_forest', 'hist_gradient_boosting']
    for algo in args.algorithms:
        if algo not in valid_algorithms:
            print(f"[!] Error: Algoritma '{algo}' tidak valid. Algoritma yang tersedia: {', '.join(valid_algorithms)}")
            return 1
    
    try:
        # Inisialisasi sistem mitigasi
        mitigation_system = NDNMitigationSystem(args.dataset, args.output, args.algorithms)
        
        # Muat dataset
        if not mitigation_system.load_data():
            return 1
        
        # Analisis traffic
        mitigation_system.analyze_traffic()
        
        # Jika hanya analisis, selesai di sini
        if args.analyze_only:
            print("[+] Analisis selesai.")
            return 0
        
        # Persiapkan fitur
        mitigation_system.prepare_features()
        
        # Latih model
        if not mitigation_system.train_models():
            print("[!] Pelatihan model gagal. Coba gunakan opsi --analyze-only untuk memeriksa dataset.")
            return 1
        
        # Terapkan mitigasi
        mitigation_system.apply_mitigation()
        
        # Buat visualisasi jika diminta
        if args.visualize:
            mitigation_system.generate_visualizations()
        
        # Buat laporan jika diminta
        if args.report:
            mitigation_system.generate_summary_report()
        
        # Ekspor konfigurasi mitigasi
        mitigation_system.export_mitigation_config()
        
        print("\n[+] Proses mitigasi selesai!")
        return 0
    
    except Exception as e:
        print(f"[!] Error tidak terduga: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())

