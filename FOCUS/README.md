# Context-Aware Network Anomaly & Attack Pattern Assessment System

## 1. Project Title
**Context-Aware Network Anomaly & Behavioural Attack Pattern Assessment System**  
An explainable, academic security monitoring framework integrating multi-model machine learning anomaly detection with host-level context correlation, deterministic risk assessment, analytical attack trees, and condition-based attack pattern assessment.

---

## 2. Objective
The primary objective of this project is to provide a transparent, modular, and non-destructive pipeline for observing network telemetry and assessing anomalous activity. Specifically, the system aims to:
- Detect traffic rate deviations against trained baselines using supervised regression.
- Flag multidimensional volume anomalies using unsupervised Isolation Forest modeling.
- Correlate active host network context (local listening/remote connected ports, PIDs, process names, and port exposure tiers) without modifying host state.
- Formulate deterministic, explainable risk scores (0–100) and severity ratings.
- Map observed indicators onto an analytical Attack Tree model.
- Assess what potential attack pattern the anomalous behaviour *may resemble* using transparent, condition-based heuristic rules.
- Maintain a structured, persistent CSV record of security events for post-incident review.

> **Academic Disclaimer**: This system is designed for academic demonstration and behavioural assessment. It does **not** claim confirmed attack classification, attack attribution, guaranteed detection accuracy, or enterprise-grade prevention capabilities.

---

## 3. Architecture & Target Pipeline Flow

The system operates strictly within an observation-first, passive monitoring paradigm:

```
                  +-----------------------------------+
                  |      Live Network Telemetry       |
                  |     (psutil byte counters)        |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |  Random Forest Baseline Predict   |
                  |  (Inbound & Outbound Expected)    |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |       Deviation Analysis          |
                  |  (|actual - predicted| / norm)    |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |  Isolation Forest Anomaly Check   |
                  |  (Unsupervised Bivariate Vector)  |
                  +-----------------+-----------------+
                                    |
                            [If Anomaly Detected]
                                    |
                                    v
                  +-----------------------------------+
                  | Host Port & Process Correlation   |
                  | (Port, PID, Process, Port Risk)   |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  | Condition-Based Attack Pattern    |
                  | Assessment (Heuristic Resemblance)|
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  | Context-Aware Risk Engine (0-100) |
                  |  (Deterministic Scoring & Tiers)  |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |     Analytical Attack Tree        |
                  |    (Indicator Verification)       |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |       Explainable Alert           |
                  |       (Terminal Console)          |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |    Security Event CSV Logger      |
                  |      (security_events.csv)        |
                  +-----------------------------------+
```

---

## 4. Machine Learning Techniques
The framework leverages a two-tier machine learning approach:

1. **Supervised Baseline Estimation (Random Forest Regressor)**:
   - **Models**: `inboundModel.joblib` and `outboundModel.joblib`.
   - **Feature**: Elapsed monitoring duration (`elapsed_time`).
   - **Target**: Expected throughput in Mbps.
   - **Role**: Establishes expected historical throughput baselines over time to compute normalized percentage deviations.

2. **Unsupervised Outlier Detection (Isolation Forest)**:
   - **Model**: `isolationForestModel.joblib`.
   - **Features**: Dual-axis throughput vector `[inbound_speed, outbound_speed]` in Mbps.
   - **Role**: Evaluates whether current multi-rate metrics reside within standard density clusters or represent multivariate outliers without requiring malicious training labels.

---

## 5. Port & Process Context Correlation
When an anomaly is flagged, the system inspects the local socket table to ground the network event in host context:
- **Port Exposure Risk**: Maps local/remote ports to exposure risk tiers (`HIGH` for ports 21, 23, 135, 139, 445; `MEDIUM` for ports 22, 80, 8080; `LOW` for port 443; `UNKNOWN` otherwise).
- **Process Identification**: Associates open connections with host PIDs and executable names via `psutil`. If process metadata cannot be resolved due to OS privileges or transient closure, it safely defaults to `Unknown`.
- **Non-Destructive Principle**: Context correlation is strictly read-only. It never terminates processes, modifies firewall rules, or executes counter-measures.

---

## 6. Risk Engine
The risk engine (`risk_engine.py`) provides deterministic, transparent heuristic scoring on a 0–100 scale:
- **ML Anomaly Detected**: +40 points
- **Port Exposure Tier**: +20 points (`HIGH`), +10 points (`MEDIUM`), 0 points (`LOW`/`UNKNOWN`)
- **Unidentified Process**: +20 points
- **Temporal Persistence (>= 3 observations)**: +20 points

### Severity Tiers
- **0–25**: `LOW`
- **26–50**: `MEDIUM`
- **51–75**: `HIGH`
- **76–100**: `CRITICAL`

---

## 7. Analytical Attack Tree
The attack tree module (`attack_tree.py`) formalizes a hierarchical qualitative decomposition of potential compromise indicators:
- **Root**: `Potential Network Compromise`
- **Branches**:
  - `Exploitable Network Exposure`: Evaluates HIGH or MEDIUM exposed ports.
  - `Abnormal Network Behaviour`: Evaluates ML anomaly and high normalized deviations (>= 50%).
  - `Suspicious Process / Connection`: Evaluates unidentified processes and persistent anomaly observations (>= 3).

The tree serves as an analytical structural reference and does not claim proven penetration.

---

## 8. Condition-Based Attack Pattern Assessment
The attack pattern assessor (`attack_pattern_assessor.py`) evaluates anomalous metrics against transparent, condition-based behavioural rules:
1. **Possible DoS/DDoS-like Traffic Surge**:
   - *Conditions*: `ML Anomaly == True`, `Inbound Deviation >= 50%`, `Consecutive Anomalies >= 3`.
   - *Explanation*: "Traffic behaviour shows a sustained inbound deviation consistent with a possible DoS/DDoS-like traffic surge."
2. **Possible Unusual Outbound Transfer**:
   - *Conditions*: `ML Anomaly == True`, `Outbound Deviation >= 50%`, `Consecutive Anomalies >= 3`.
   - *Explanation*: "Traffic behaviour shows a sustained outbound deviation that may warrant investigation as unusual outbound transfer activity."
3. **Possible Suspicious Network Service Activity**:
   - *Conditions*: `ML Anomaly == True`, `Port Risk == HIGH`, `Process Name == Unknown/None`.
   - *Explanation*: "An anomalous traffic event is associated with a high-exposure port and an unidentified process."
4. **Unclassified Network Anomaly**:
   - Assigned when an ML anomaly occurs but specific corroborating conditions for defined patterns are not satisfied.
5. **Multiple Pattern Co-occurrence**:
   - When multiple rules match, the most dominant pattern is selected as primary, secondary patterns are retained as additional evidence, and evidence escalates to `HIGH`.

---

## 9. Security Event Logging
Alerts are recorded in [`security_events.csv`](file:///d:/My%20Projects/Cyber%20Project/FOCUS/security_events.csv) using a fixed, deterministic schema:
- `timestamp`: Event creation date and time.
- `severity`: Assigned risk severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `risk_score`: Heuristic score (0–100).
- `ml_anomaly`: Flag indicating ML detection (`YES`/`NO`).
- `isolation_forest_score`: Unsupervised anomaly score.
- `inbound_actual`, `inbound_expected`, `inbound_deviation`: Inbound throughput metrics.
- `outbound_actual`, `outbound_expected`, `outbound_deviation`: Outbound throughput metrics.
- `port`, `port_risk`: Host port and exposure tier.
- `pid`, `process`: Associated PID and process name.
- `consecutive_anomalies`: Anomaly persistence count.
- `reasons`: Semicolon-delimited reasons including risk breakdown, `possible_pattern=...`, and `evidence=...`.

---

## 10. How to Run

### Prerequisites
Install dependencies from `requirements.txt`:
```bash
pip install -r requirements.txt
```

### Main Menu Interface (CLI)
Launch the unified interactive console:
```bash
python main.py
```
Menu Options:
- `1`: Run the multi-threaded local port scanner (respects `WhitePorts.txt`).
- `2`: Start the real-time ML Network Anomaly Monitor.
- `3`: View recent logged security events from `security_events.csv`.
- `4`: Display local system hardware and platform information.
- `0`: Exit.

### Direct Execution
- **Run Monitor Directly**:
  ```bash
  python aiNetworkSpikeDetector.py
  ```
- **Run Risk Engine Self-Tests**:
  ```bash
  python risk_engine.py
  ```
- **Run Attack Tree Self-Tests**:
  ```bash
  python attack_tree.py
  ```
- **Run Attack Pattern Unit Tests**:
  ```bash
  python test_attack_pattern_assessor.py
  ```
- **Run Security Logger Self-Tests**:
  ```bash
  python security_logger.py
  ```

---

## 11. Testing Summary
Comprehensive testing evidence is documented in detail in [`TESTING_EVIDENCE.md`](file:///d:/My%20Projects/Cyber%20Project/FOCUS/TESTING_EVIDENCE.md). A summary of executed tests:
- **Environment**: Python 3.12.10 (64-bit AMD64) on Windows 11.
- **Core Imports**: 8/8 core modules imported cleanly with zero errors.
- **Port Scanner**: Controlled local test on port 7777 detected; whitelisted port 135 excluded; non-destructive.
- **Random Forest**: Loaded `inboundModel.joblib` and `outboundModel.joblib`; successfully generated expected baselines.
- **Isolation Forest**: Loaded `isolationForestModel.joblib`; verified normal vs anomaly prediction and sample scoring.
- **Deviation Analysis**: Verified percentage deviations for inbound and outbound traffic.
- **Context Correlation**: Verified active socket lookup (PID, process name, port risk) and safe fallback on unmapped ports.
- **Risk Engine**: 5/5 test cases passed (scores 0–100, severities LOW to CRITICAL).
- **Attack Tree**: Baseline, anomaly, and boundary threshold tests (49.99% vs 50.00%) passed.
- **Attack Pattern Assessor**: 7/7 unit tests passed covering all primary patterns, unclassified states, multi-matches, and boundary conditions.
- **Security Logger**: Validated CSV schema, event formatting, and retrieval via `view_security_events()`.
- **End-to-End Pipeline**: Verified normal monitor execution and controlled anomaly simulation with full alert generation and CSV logging.
- **Model Integrity**: Model files verified intact bit-for-bit via SHA-256 hashes.
- **Safety**: Verified no active process termination, firewall changes, IP blocking, or calls to disconnected scripts.

---

## 12. Project Limitations & Ethical Scope
- **Pattern Resemblance vs Confirmation**: Detected patterns represent statistical and contextual resemblance; they do not prove malicious intent or exploit execution.
- **Permission Boundary**: Process identification relies on operating system socket query permissions. Without elevated administrative rights, some processes may resolve as `Unknown`.
- **Baseline Context**: The Random Forest baselines reflect the characteristics of the captured training dataset (`network_data_log.csv`) and are not universal to all network topologies.
- **Passive Operation**: The system does not incorporate active intrusion prevention or automated response by design to ensure system safety and avoid service disruption.
