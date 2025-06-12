# SecureScope
SecureScope was developed to serve as a Large Language Model (LLM) enhanced Intrusion Detection System (IDS). Its primary objective is to showcase our proficiency in project development for the Programming Techniques in Special Languages course, undertaken during my first semester of senior year. The project demonstrates proficiency in network traffic analysis, real-time packet inspection, feature extraction using PyShark, and the integration of machine learning models (LightGBM) with LLMs for enhanced threat detection and interpretability. SecureScope highlights our ability to combine traditional cybersecurity techniques with modern AI to build intelligent and responsive security systems.

## Project Overview

SecureScope combines traditional cybersecurity techniques with modern AI to build an intelligent and responsive security system capable of:

- **Real-time Network Traffic Analysis**: Live packet capture and inspection using PyShark
- **Machine Learning Threat Detection**: LightGBM-based model for behavioral anomaly detection
- **Threat Intelligence Integration**: IP reputation checking against known malicious sources
- **Dual-Layer Security**: Both offline and online threat validation for comprehensive protection

## Architecture

The system consists of several key components:

### Core Components

- **IDS Engine (`ids.py`)**: Main detection system that orchestrates packet capture, feature extraction, and threat analysis
- **ML Detector (`ml_detector.py`)**: Machine learning component for behavioral threat detection
- **IP Checker (`ip_checker.py`)**: Threat intelligence module for IP reputation verification
- **IoC Updater (`ioc_updater.py`)**: Automated threat intelligence updater

### Key Features

- **Hybrid Detection Approach**: Combines machine learning behavioral analysis with threat intelligence
- **Flow-Based Analysis**: Tracks network flows to build comprehensive traffic profiles
- **Configurable Detection**: Flexible configuration system for different deployment scenarios
- **Real-Time Processing**: Live network monitoring with immediate threat alerting

## Technical Implementation

### Machine Learning Integration

The ML component uses a pre-trained LightGBM model trained on a select columns from  **UNSW-NB15 dataset**, a comprehensive network intrusion detection dataset developed by the Australian Centre for Cyber Security (ACCS). 

The model analyzes network flow features including:
- Flow duration and packet statistics
- Byte transfer patterns
- Port and protocol information
- Packet timing characteristics

**Dataset Source**: Training and testing datasets were sourced from the [nospammers repository](https://github.com/ushukkla/nospammers) which provides accessible versions of the UNSW-NB15 training and testing sets.

### Feature Engineering

SecureScope extracts and processes multiple network flow features:
- Source/Destination ports and protocols
- Forward/Backward packet counts and sizes
- Flow bytes per second and packets per second
- Mean packet lengths for directional flows

### Threat Intelligence

The system integrates with:
- **Offline Database**: Local CSV-based abuseipdb repo imported malicious IP database 
- **Online API**: AbuseIPDB integration for real-time threat intelligence
- **Automated Updates**: GitHub-based IoC feed synchronization

## Installation & Setup

### Prerequisites

```bash
pip install pyshark pandas scikit-learn lightgbm joblib requests GitPython
```

### Configuration

Edit `Conf.conf` to customize your deployment:

```ini
[params]
sniffing = 1          # Enable/disable packet capture
NIC = Wi-Fi           # Network interface for monitoring
IoC = 0               # Download IoC updates (1/0)
check_ioc = 1         # Offline (1) vs Online (0) IP checking
packet_limit = 10     # Number of packets to analyze
```

### Usage

Run SecureScope with the configuration section:

```bash
python main.py params
```

## Detection Capabilities

### Threat Detection Levels

1. **ML-Only Detection**: Behavioral anomaly detection through machine learning
2. **IoC-Only Detection**: Known malicious IP identification
3. **Consensus Detection**: Critical alerts when both ML and IoC systems agree

## Project Significance

SecureScope demonstrates the successful integration of multiple cybersecurity domains:

- **Network Security**: Real-time traffic monitoring and analysis
- **Machine Learning**: Behavioral anomaly detection using ensemble methods
- **Threat Intelligence**: Integration with external threat feeds
- **Software Engineering**: Modular, maintainable codebase with proper configuration management

This project represents a comprehensive approach to modern cybersecurity, showcasing the ability to combine traditional security techniques with cutting-edge AI/ML technologies to create intelligent, adaptive defense systems.ts

- Integration with additional threat intelligence sources
- Enhanced ML model training with larger datasets
- Web-based dashboard for real-time monitoring
- Support for additional network protocols and features
- Automated response and mitigation capabilities
