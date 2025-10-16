# Simulation-Framework-Mini-NDN-Attacks-on-Ubuntu-Python

## NDN Security Research Platform
Welcome to the **Telkom University Named Data Networking (NDN) Research Platform**.  
This is a powerful simulation environment built on **Mini-NDN** to study and analyze the NDN architecture, with a special focus on **security threat models**.  
This project simulates a complex campus network topology and implements common attacks such as the *Interest Flooding Attack (IFA)* and *Cache Poisoning Attack (CPA)* for research and analysis purposes.

---

### 📜 Table of Contents
- [Core Concepts](#-core-concepts)
  - [Named Data Networking (NDN)](#named-data-networking-ndn)
  - [Security Threat Models](#security-threat-models)
- [✨ Key Features](#-key-features)
- [📁 Project Structure](#-project-structure)
- [💻 System Specifications & Requirements](#-system-specifications--requirements)
- [🚀 Installation & Setup](#-installation--setup)
- [▶️ How to Run the Simulation](#️-how-to-run-the-simulation)
- [📊 Understanding the Simulation Output](#-understanding-the-simulation-output)
- [🌐 Topology Configuration](#-topology-configuration)
- [📚 Research References](#-research-references)
- [📝 License & Author](#-license--author)

---

### 💡 Core Concepts

#### Named Data Networking (NDN)
Named Data Networking (NDN) is a future Internet architecture that shifts communication from a **host-centric** model (based on IP addresses) to a **data-centric** model (based on content names).  
In NDN, communication is driven by data requests (Interests) from consumers rather than end-to-end host connections.

The core components simulated in this platform include:

* **Content Store (CS):** An in-network caching system on every router that stores Data packets to reduce latency and network traffic.  
* **Pending Interest Table (PIT):** Tracks unsatisfied Interest packets, enabling Interest aggregation and Data multicasting.  
* **Forwarding Information Base (FIB):** Similar to an IP routing table, the FIB stores forwarding information for Interest packets based on name prefixes.  
* **Faces:** An abstraction for communication interfaces, which can represent physical or virtual connections between nodes.

---

#### Security Threat Models
This simulation framework implements two major security attack models in the NDN architecture:

**1. Interest Flooding Attack (IFA)**  
* **Vector:** The attacker floods the network with Interest packets for non-existent content.  
* **Target:** To exhaust the PIT (Pending Interest Table) resources in routers, leading to a Denial of Service (DoS) for legitimate users.  
* **Implementation:** External attacker nodes (`a_ext`) continuously send Interest packets for random, non-existent content names.

**2. Cache Poisoning Attack (CPA)**  
* **Vector:** The attacker injects malicious or fake data into the network.  
* **Target:** To compromise the integrity and availability of cached data in the Content Store (CS).  
* **Implementation:** Internal attacker nodes (`a_int`) request legitimate content, then immediately send a fake version of the same data name to poison the cache before the authentic data arrives.

---

### ✨ Key Features
* **Realistic Simulation:** Built on Mini-NDN to emulate real NDN daemons (NFD) and routing protocols (NLSR).  
* **Flexible Topology:** Easily configure complex network topologies via `.conf` files.  
* **Attack Simulation:** Integrated implementations of IFA and CPA with customizable parameters.  
* **Comprehensive Data Collection:** Automatically generates CSV traffic datasets, per-node activity logs, and `.pcap` packet captures.  
* **Performance Metrics Analysis:** Monitors CPU/Memory usage, CS hit ratio, PIT utilization, and forwarding performance.  
* **Interactive CLI Mode:** Allows direct access to each node for debugging or experiment control via the Mini-NDN shell.

---

### 📁 Project Structure
The main file and directory organization is as follows:
- main.py # Main simulation execution script
- dfn.conf # Example network topology (mesh type)
- tree.conf # Example network topology (tree type)
- mitigation.py # Optional script for mitigation mechanisms
- output_{topology_name}/ # Default output directory
- raw_data/ # Logs, packet captures, and raw metrics
- statistics/ # Summarized performance statistics
- dataset/ # Traffic dataset (CSV format)
- analysis/ # Post-simulation analysis results

---

### 💻 System Specifications & Requirements
**Operating System:**  
Ubuntu 20.04 LTS or 22.04 LTS (recommended)

**Core Dependencies:**  
- Mini-NDN (for network emulation)  
- NDN Forwarding Daemon (NFD)  
- Named Link State Routing Protocol (NLSR)

**Programming Environment:**  
- Python 3.8 or higher  
- Required Python Libraries: `pandas`  
- Utilities: `git`, `tcpdump`

---

License: MIT License
Author: Muhammad Raga Titipan (201012310022)
Version: 1.2.0
Codename: NDNSecure
