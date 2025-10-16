# Simulation-Framework-Mini-NDN-Attacks-on-Ubuntu-Python

## NDN Security Research Platform
Welcome to the Telkom University Named Data Networking (NDN) Research Platform. This is a powerful simulation environment built on **Mini-NDN** to study and analyze the NDN architecture, with a special focus on security threat models. This project simulates a complex campus network topology and implements common attacks such as the *Interest Flooding Attack (IFA)* and *Cache Poisoning Attack (CPA)* for research and analysis purposes.


*A conceptual visualization of a network topology that can be simulated.*

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
NDN is a future internet architecture that shifts the communication paradigm from a host-centric model (based on IP addresses) to a data-centric model (based on content names). In NDN, communication is driven by data requests from Consumers, not by connections between hosts.

The core components simulated in this platform include:
* **Content Store (CS):** An in-network caching system on every router that stores Data packets to reduce latency and network traffic.
* **Pending Interest Table (PIT):** Tracks unsatisfied Interest packets, enabling Interest aggregation and Data multicasting.
* **Forwarding Information Base (FIB):** Similar to a routing table in IP, the FIB stores forwarding information for Interest packets based on name prefixes.
* **Faces:** An abstraction for communication interfaces, which can be physical interfaces or virtual connections between nodes.

#### Security Threat Models
This platform specifically implements two significant attack models against the NDN architecture:

**1. Interest Flooding Attack (IFA)**
* **Vector:** An attacker floods the network with Interest packets for non-existent content.
* **Target:** To exhaust the PIT resources on routers, causing a Denial of Service (DoS) for legitimate users.
* **Implementation:** External `attacker` nodes (`a_ext`) continuously send requests for random, non-existent content names.

**2. Cache Poisoning Attack (CPA)**
* **Vector:** An attacker injects malicious or false data into the network.
* **Target:** To compromise the integrity and availability of data in the routers' Content Store (CS).
* **Implementation:** An internal `attacker` node (`a_int`) requests legitimate content and then quickly sends a fake version of the data with the same name to "poison" the cache before the authentic data arrives.

---

### ✨ Key Features
* **Realistic Simulation:** Built on the Mini-NDN foundation to run actual NDN daemons (NFD) and routing protocols (NLSR).
* **Flexible Topology:** Easily configure complex network topologies through intuitive `.conf` files.
* **Attack Simulation:** Built-in implementation for IFA and CPA attacks with configurable rates.
* **Comprehensive Data Collection:** Generates traffic datasets in CSV format, per-node activity logs, performance statistics, and packet capture (`.pcap`) files.
* **Performance Metrics Analysis:** Tracks crucial metrics like router CPU/Memory utilization, CS hit ratio, and PIT satisfaction ratio.
* **Interactive Mode:** Provides a Mini-NDN CLI for direct interaction and debugging with nodes inside the running topology.

---

### 📁 Project Structure
The primary file and directory structure for this project is as follows:
