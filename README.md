# 🛡️ Hybrid Machine Learning Approach for Detecting DDoS Attacks in Simulated IoT Networks

[![Python](https://img.shields.io/badge/Python-3.10-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.31-red.svg)](https://streamlit.io/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.6.1-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-Academic-green.svg)](#license)

> **Final Year Project — Bachelor of Science in Computer Science**
> **SIMAD University · Faculty of Computing · June 2026**

A hybrid machine learning framework that detects Distributed Denial-of-Service (DDoS) attacks in IoT networks by combining Random Forest, K-Nearest Neighbors, and Gradient Boosting through a stacking ensemble with a Logistic Regression meta-learner.

🌐 **Live Demo:** [iot-ddos-detection.streamlit.app](https://iot-ddos-detection.streamlit.app)

---

## 👥 Team

| Name | Primary Contribution | GitHub |
|------|---------------------|--------|
| **Zamzam Hassan Ali** | IoT Network Simulation, Dataset Generation & Dashboard | [@Zamzam005](https://github.com/Zamzam005) |
| **Hafso Hussein Ahmed** | Machine Learning Model Training & Dashboard | [@hafsahussein-99](https://github.com/hafsahussein-99) |

*The Streamlit dashboard was developed collaboratively by both team members.*

**Supervisor:** Lul Farah Abdullahi
**Institution:** SIMAD University, Mogadishu, Somalia

---

## 🎯 Project Overview

The rapid growth of Internet of Things (IoT) networks has introduced major cybersecurity challenges. IoT devices have limited processing power and weak security, making them prime targets for DDoS attacks. Traditional signature-based detection systems fail against new attack patterns, and single machine learning models often produce too many false alarms.

This project addresses these challenges by:

1. **Building a simulated IoT network** using Mininet (10 IoT devices, 2 fog nodes, 1 gateway, 1 cloud server)
2. **Generating realistic traffic** — benign IoT communication plus 4 DDoS attack types (SYN, UDP, ICMP, HTTP floods)
3. **Training a hybrid stacking ensemble** that achieves zero false positives on the test set
4. **Deploying a multi-page Streamlit dashboard** for real-time PCAP analysis

---

## 📊 Results

| Metric | Value |
|--------|-------|
| **Accuracy** | 99.99% |
| **Precision** | 100.00% (zero false positives) |
| **Recall** | 99.97% |
| **F1-Score** | 99.98% |
| **AUC** | 1.0000 |
| **Detection Time** | 19.15 ms per flow |
| **Dataset Size** | 341,699 flow instances |
| **Training Time** | 955 seconds (~16 minutes) |

### Comparison with baseline classifiers

| Model | Accuracy | Precision | F1-Score | Detection Time |
|-------|----------|-----------|----------|----------------|
| Random Forest (alone) | 99.97% | 99.95% | 99.96% | 0.50 ms |
| KNN (K=7, alone) | 99.85% | 99.78% | 99.84% | 4.20 ms |
| Gradient Boosting (alone) | 99.92% | 99.88% | 99.91% | 1.80 ms |
| Decision Tree (alone) | 99.89% | 99.82% | 99.87% | 0.30 ms |
| SVM (alone) | 99.45% | 99.32% | 99.45% | 2.10 ms |
| **Proposed Hybrid (RF+KNN+GB → LR)** | **99.99%** | **100.00%** | **99.98%** | 19.15 ms |

---

## 🛠️ Tech Stack

### Simulation & Traffic Generation
- **Mininet** — IoT network topology emulation
- **scapy** — Custom benign IoT traffic generation
- **hping3** — DDoS attack generation (SYN, UDP, ICMP)
- **Custom Python script** — HTTP flood attack
- **tshark** — Packet capture (PCAP files)
- **nfstream** — Flow-level feature extraction

### Machine Learning
- **scikit-learn 1.6.1** — Model implementations
- **imbalanced-learn** — SMOTE for class balancing
- **Google Colab** — Model training environment
- **joblib** — Model serialization

### Dashboard & Deployment
- **Streamlit 1.31** — Web interface framework
- **pandas, numpy** — Data processing
- **matplotlib, seaborn** — Visualizations
- **Streamlit Cloud** — Live deployment

---

## 📁 Repository Structure

```
iot-ddos-detection-fyp/
│
├── dashboard/                          # Streamlit web application
│   ├── dashboard.py                    # Main dashboard code (5 pages)
│   ├── hybrid_model.pkl                # Trained stacking ensemble (37 MB)
│   ├── scaler.pkl                      # MinMax scaler for features
│   ├── requirements.txt                # Python dependencies
│   └── graphs/                         # Performance visualizations
│       ├── confusion_matrix.png
│       ├── roc_curve.png
│       ├── feature_importance.png
│       └── topology_drawing.png
│
├── sample_pcaps/                       # Ready-to-use test files
│   ├── benign_small.pcap               # Normal IoT traffic sample
│   ├── syn_flood_small.pcap            # SYN flood attack sample
│   ├── udp_flood_small.pcap            # UDP flood attack sample
│   ├── icmp_flood_small.pcap           # ICMP flood attack sample
│   └── http_flood_small.pcap           # HTTP flood attack sample
│
├── simulation/                         # Mininet IoT network simulation
│   └── scripts/                        # Traffic generation scripts
│       ├── topology.py                 # Network topology builder
│       ├── benign_traffic.py           # Normal IoT traffic generator
│       ├── server_listener.py          # Cloud server listener
│       ├── http_flood.py               # HTTP flood attack script
│       └── extract_features.py         # nfstream feature extractor
│
├── .gitignore                          # Git ignore rules
├── runtime.txt                         # Python version for deployment
└── README.md                           # You are here
```

---

## 🚀 Quick Start

### Option 1 — Try the live demo (easiest)

Visit **https://iot-ddos-detection.streamlit.app** and:

1. Click the **🔍 Live Detection** tab
2. Download a sample PCAP file from the [`sample_pcaps/`](sample_pcaps/) folder of this repo
3. Upload the PCAP to the dashboard
4. View real-time DDoS analysis with attack-type breakdown

### Option 2 — Run locally

#### Prerequisites
- Python 3.10+
- pip
- Git

#### Installation

```bash
# Clone the repository
git clone https://github.com/Zamzam005/iot-ddos-detection-fyp.git
cd iot-ddos-detection-fyp/dashboard

# Install dependencies
pip install -r requirements.txt

# Run the dashboard
streamlit run dashboard.py
```

The dashboard opens at `http://localhost:8501`.

#### Test it immediately

After the dashboard opens:
1. Click the **🔍 Live Detection** tab
2. Click the **Upload** button
3. Select any file from the `sample_pcaps/` folder of this repo
4. View the analysis results

---

## 🧪 Sample Test Files

The `sample_pcaps/` folder contains five pre-prepared PCAP files for immediate testing — one benign sample and one for each DDoS attack type:

| File | Type | Size | Expected Result |
|------|------|------|-----------------|
| `benign_small.pcap` | Normal IoT traffic | ~25 MB | ✅ Safe (Green banner) |
| `syn_flood_small.pcap` | SYN flood DDoS attack | ~25 MB | 🚨 Threat detected (Red banner) |
| `udp_flood_small.pcap` | UDP flood DDoS attack | ~25 MB | 🚨 Threat detected (Red banner) |
| `icmp_flood_small.pcap` | ICMP flood DDoS attack | ~25 MB | 🚨 Threat detected (Red banner) |
| `http_flood_small.pcap` | HTTP flood DDoS attack | ~25 MB | 🚨 Threat detected (Red banner) |

These samples are smaller representative subsets of the full simulation captures (50,000 packets each), suitable for quick testing while maintaining the statistical characteristics of the original full captures.

---

## 🔬 How It Works

### Architecture pipeline

```
PCAP file upload
       ↓
Feature extraction (scapy, 15 features)
       ↓
MinMax scaling
       ↓
┌──────────────────────────────┐
│  Random Forest               │
│  K-Nearest Neighbors (K=7)   │  ← Base learners
│  Gradient Boosting           │
└──────────────────────────────┘
       ↓
Logistic Regression (meta-learner)
       ↓
Binary classification: Benign (0) / Attack (1)
       ↓
Per-attack-type heuristic classifier
       ↓
Dashboard output (verdict, charts, attacker IPs, CSV report)
```

### Top 5 most informative features

| Rank | Feature | Importance |
|------|---------|------------|
| 1 | total_length_fwd_packets | 0.2328 |
| 2 | total_fwd_packets | 0.2229 |
| 3 | flow_duration | 0.1341 |
| 4 | flow_iat_mean | 0.1030 |
| 5 | fwd_packets_per_second | 0.0845 |

---

## 📸 Dashboard Pages

The Streamlit dashboard has 5 navigable pages:

1. **🏠 Home** — Project overview and key performance indicators
2. **🔍 Live Detection** — Upload PCAP files and view real-time analysis
3. **📊 Model Performance** — Evaluation metrics and supporting charts
4. **🏗️ System Architecture** — Methodology and pipeline explanation
5. **ℹ️ About the Team** — Authors and institutional information

---

## 🔄 Reproducing the Full Simulation (Advanced)

To regenerate the dataset from scratch using Mininet, you'll need a Debian/Ubuntu Linux machine.

```bash
# 1. Install required tools
sudo apt update
sudo apt install mininet hping3 tshark python3-scapy

# 2. Start the IoT network topology
cd simulation/scripts
sudo python3 topology.py

# 3. In a second terminal — start the server listener
sudo python3 server_listener.py

# 4. Generate benign traffic (run inside Mininet host)
sudo python3 benign_traffic.py

# 5. Launch DDoS attacks (example: SYN flood)
sudo hping3 -S --flood -p 80 10.0.0.1

# 6. Capture and extract features
sudo tshark -i any -w capture.pcap
sudo python3 extract_features.py capture.pcap > iot_dataset.csv
```

---

## 📊 Dataset

The full dataset contains **341,699 flow instances** with **16 features** (15 inputs + class label):

- **Benign traffic:** 194,631 flows (57.0%)
- **DDoS attack traffic:** 147,068 flows (43.0%) covering SYN, UDP, ICMP, and HTTP floods

**Note:** Full raw PCAP files (~4.1 GB total) are not included in the repository due to size. For the full captures or the complete `iot_dataset.csv`, please contact the authors or regenerate using the simulation scripts above. Smaller test samples are provided in the `sample_pcaps/` folder.

---

## 🧪 Model Training

Model training was performed in **Google Colab** for GPU acceleration. The training pipeline performs:

1. Data loading from `iot_dataset.csv`
2. Train/validation/test split (70/15/15, stratified)
3. MinMax scaling
4. SMOTE oversampling (applied only to training set)
5. Hyperparameter configuration for each base learner
6. Stacking ensemble training with 5-fold cross-validation
7. Evaluation on the held-out test set
8. Model serialization to `hybrid_model.pkl` and `scaler.pkl`

---

## ⚠️ Limitations

1. **Simulation-only validation** — The model has only been tested on Mininet-simulated traffic. Real-world IoT deployment validation is needed.
2. **Binary classification** — The model classifies flows as benign or attack, but does not differentiate attack types at the model level (the dashboard uses a separate heuristic for that).
3. **No online learning** — The model requires manual retraining when new attack patterns emerge.
4. **Limited attack scope** — Only 4 DDoS attack types simulated (SYN, UDP, ICMP, HTTP). Slow-rate and application-layer attacks were not included.

---

## 🔮 Future Work

- Deploy on real IoT gateway hardware for live validation
- Extend to multi-class classification (identify specific attack type)
- Integrate online learning for continuous adaptation
- Add low-rate and application-layer attack detection
- Combine with SDN-based automated mitigation

---

## 📖 Citation

If you use this work, please cite:

```bibtex
@thesis{zamzam_hafso_2026_ddos,
  author  = {Zamzam Hassan Ali and Hafso Hussein Ahmed},
  title   = {Hybrid Machine Learning Approach for Detecting DDoS Attacks
             in Simulated IoT Networks},
  school  = {SIMAD University},
  year    = {2026},
  type    = {BSc Thesis},
  address = {Mogadishu, Somalia}
}
```

---

## 📝 License

This project is academic work submitted in partial fulfillment of the BSc in Computer Science at SIMAD University. The code is provided for educational and research purposes.

For reuse in commercial or other academic projects, please contact the authors.

---

## 📬 Contact

- **Zamzam Hassan Ali** — GitHub: [@Zamzam005](https://github.com/Zamzam005)
- **Project Repository:** https://github.com/Zamzam005/iot-ddos-detection-fyp
- **Live Demo:** https://iot-ddos-detection.streamlit.app

---

## 🙏 Acknowledgments

We extend our deepest gratitude to:

- **Lul Farah Abdullahi** — Our supervisor, for her patient guidance and invaluable feedback throughout this research
- **SIMAD University, Faculty of Computing** — For providing the academic environment and resources
- **The open-source community** — Mininet, scikit-learn, Streamlit, scapy, and all the tools that made this project possible
- **Our families** — For their unwavering support and prayers

> "In the name of Allah, the Most Gracious and the Most Merciful."

---

**Built with ❤️ at SIMAD University · 2026**
