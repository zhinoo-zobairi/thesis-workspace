# A Comparison of Neural-Network-Based Intrusion Detection against Signature-Based Detection in IoT Networks

🔗 [anchor: Motivation] 🔗 [anchor: Grundlagen]

Message Queuing Telemetry Transport (MQTT) [53] is the most widespread protocol for edge- and cloud-based Internet of Things (IoT) solutions. Hence, an IDS for an IoT environment has to consider MQTT-specific attacks.

## Problem

🔗 [anchor: Problemstellung]

* Many papers on ML-based intrusion detection do not compare their results to a proper baseline of signature-based IDS.
* The number of IoT devices grew from 14.3 billion (2022) to 16.7 billion (2023) and now to 21.1 billion in 2025; this massive expansion exposes a huge attack surface.
* Two main IDS types exist:

  * **Anomaly-based:** compares to the mean/variance of normal behavior, but not all attacks behave abnormally.
  * **Signature-based:** relies on predefined attack patterns to minimize false alarms.
* Machine learning has recently been used to learn attack patterns directly from data.

  * Dini et al. showed that decision trees performed best among seven tested methods.
  * A 2021 survey favored deep learning IDS (≥2 layers).
* Pitfall #6 by Arp et al.: inappropriate baseline; makes it impossible to demonstrate real improvements.
* Only Gray et al. compared a random forest classifier against Suricata, but using a limited rule set, making results unrealistic.
* Cahyo et al. compared 20 papers (2016–2020), showing that hybrid IDSs (signature + anomaly) remain mostly theoretical.
* **Conclusion:** the majority of ML-based IDS publications fail to compare against proper baselines.

## Approach

A comparison study:

* One of the best-performing DLIDS models was selected and compared against **Snort** (a signature-based IDS).
* Two scenarios were studied:

  1. IoT devices as **attack targets**.
  2. IoT devices as **attack sources** (e.g., DDoS).

### Data and Methodological Setup

* Following **John McHugh’s** argument 🔗 [anchor: Challenges]:

  > Either the training data must accurately reflect real-world conditions, or realistic, environment-specific data must be available for each deployment.
  > Network traffic evolves constantly, many benchmark datasets fail to represent this.
* The **FAIR principles** (findability, accessibility, interoperability, reusability) were adopted to ensure transparent and reproducible data use.
* Classification criteria included: dataset used, anomaly vs multiclass detection, ML methods applied, baselines, and model reproducibility (availability of code/data).
* Two main research patterns:

  * Some compare ML results against **published baselines**.
  * Others **implement and compare** multiple ML approaches.

### Metric Design and Evaluation

* To ensure comparability with Hindy et al., identical evaluation formulas were used.
* Metrics (accuracy, precision, recall, F1) were extended for **multiclass tasks** using macro-averaging (since there’s no single “positive” class).
* Training involved **5-fold cross-validation** with **early stopping** (training halts when validation stops improving).

### Dataset Replication and Adjustments

1. Used the **original MQTT-IoT-IDS2020 dataset** (publicly available), not Khan et al.’s modified version.
2. Aggregated multiple CSV files into a single dataset.
3. Observed severe class imbalance (Sparta 61%, MQTT Brute-force 31%).
4. Khan et al.’s published ratios differed drastically.
5. Upon inquiry, the first author mentioned possible use of resampling (oversampling/SMOTE/undersampling).
6. To align results, only 200,000 packets were retained from each major attack class (undersampling).
7. Used **stratified 5-fold cross-validation** to preserve class ratios across folds.

### Identified Problems

| Problem ID               | Issue                                | What Khan et al. did (or missed)                                             | What Replicators did / argued                         | Why it matters             |
| ------------------------ | ------------------------------------ | ---------------------------------------------------------------------------- | ----------------------------------------------------- | -------------------------- |
| **P2 Missing Values**    | Used median to fill missing fields   | Applied median even to irrelevant features (e.g., TCP fields in UDP packets) | Replaced with unset/zero when protocol not applicable | Prevents false patterns    |
| **P3 Feature Selection** | Vague feature list, unclear encoding | Claimed 52 features; replicators found 48                                    | Couldn’t replicate preprocessing exactly              | Undermines reproducibility |
| **P4 Feature Scaling**   | Scaled using dataset min/max         | Dataset-dependent, not protocol-aware                                        | Adopted protocol-defined min–max ranges               | Improves generalization    |

### Model and Design Decisions

* Flow data were avoided because in real time, full flow reconstruction is rarely possible.
* Models used **packet-based data**, consistent with how Snort and Suricata analyze traffic.
* Rebuilt Khan’s model and added **protocol-aware scaling** instead of dataset-only scaling.
* Removed **IP and timestamp** fields to prevent data leakage, since fixed IPs and times in the testbed created artificial performance.
* Low standard deviation across folds confirmed stable cross-validation.

> “If I run the same IoT network again tomorrow, will my model still detect attacks correctly?”

## Dataset / Experiment

### Replication of Dataset

* The authors recreated the IoT testbed using the **CORE network emulator**, generating new network traces closely resembling the original dataset.
* They tested two models:

  1. **Adopted Scaling**: protocol-aware scaled features but retained IP and timestamps.
  2. **Without IP/Timestamp**: removed those to encourage behavioral learning.

Both were evaluated on four conditions:

| Experiment                | Description                                   | Key Findings                                                                                             |
| ------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| **Original Dataset**      | Same data as training                         | Perfect accuracy (memorization).                                                                         |
| **New Dataset (UP Scan)** | Fresh network traffic with same topology      | Accuracy and recall dropped drastically; poor generalization.                                            |
| **Full Port Scan**        | All 65,535 ports scanned instead of top 1,000 | “Without IP/Timestamp” model achieved 86% recall, proving behavioral learning; “Adopted Scaling” failed. |
| **Sensor Scan**           | Different target device                       | Confirmed sensitivity to topology and environment.                                                       |

> Both models’ performance collapsed under new conditions, revealing reliance on dataset-specific patterns rather than true behavioral cues.
> This weakness was most visible in **MQTT brute-force** detection, where class imbalance caused misclassification as benign traffic. 🔗 [anchor: Motivation]

### Sensor Update Experiment

* Attack traffic remained the same, but benign traffic was modified.
* Introduced firmware update traffic via the **MUP Protocol**, producing large MQTT messages unlike the small periodic packets in the original dataset.
* The question: *Would the model misclassify new benign traffic as attacks?*
* Result: both models handled it well, no false alarms, even improved performance on update traffic.

### Zero-Day Attack Experiment

* Tested both models against a **DoS-New-IPv6** attack (from the THC toolkit).
* This was a **zero-day** scenario, unseen during training.
* The feed-forward model lacked an output class for this attack, forcing misclassification as “benign.”
* Three out of five retrained models detected it; two failed, proving **unstable zero-day detection** and confirming that unseen traffic isn’t consistently recognized as malicious. 🔗 [anchor: Challenges]

### Snort Evaluation

* **Snort 3.1.66** was used as the signature-based comparison system.
* Configured variables: `HOME_NET`, `EXTERNAL_NET`, and enabled inspectors (`port_scan`, `indp`).
* Rules used:

  * SSH brute-force → 30 connections from same source in 60s.
  * MQTT brute-force → repeated failed authentications (reason code 5).
* Ran Snort on **PCAP files** from MQTT-IoT-IDS2020-UP using:

  ```bash
  snort -r traffic.pcap -c snort.conf -A console
  ```
* Compared Snort’s alerts to ground truth labels.

| Observation         | Explanation                                                                                                |
| ------------------- | ---------------------------------------------------------------------------------------------------------- |
| 100% Precision      | No false positives (only relevant rules enabled).                                                          |
| <100% Recall        | Some attacks not detected due to threshold logic (e.g., Sparta slow brute-force attempts below threshold). |
| UDP scan recall low | Snort didn’t see enough bidirectional communication (missing replies).                                     |

> Snort’s logic is deterministic but rigid, its perfect precision reflects tight rule design, not adaptability.

## Results

🔗 [anchor: Evaluation]

* A signature-based IDS (Snort) with minimal configuration **outperformed** the tested neural network even under minor traffic changes.
* DLIDS failed to detect zero-day attacks and generalized poorly to new or shifted network traffic.
* This reveals systematic issues in dataset design and evaluation methods.

## Limitations

🔗 [anchor: Challenges]

* **Pitfalls identified by Arp et al.:**

  * P1: Sampling bias (dataset ≠ real traffic).
  * P6: Inappropriate baseline.
  * P7: Incomplete performance metrics.
  * P8: Base rate fallacy.
* **Zola et al.:** ML models ignore malware’s evolving nature.
* ML-IDS are vulnerable to **data poisoning, input manipulation, model inversion**.
* **Environmental diversity:** dynamic networks evolve faster than datasets.
* **Class imbalance:** inflated metrics from skewed datasets (e.g., DoS dominating).
* **Synthetic augmentation:** increases volume but not diversity, same attack tools, limited variability.
* **Recording bias:** time/source leakage, e.g., TTL features unintentionally revealing timing patterns.
* **Overfitting:** models memorize dataset structure, not domain behavior.
* **Dimpled Manifold Effect:** new data creates local distortions, not smooth generalization.
* **Overkill argument:** attack–benign distinction is so large that fixed thresholds can mimic DL performance.

> “Don’t measure how well your model classifies packets; measure how well it detects attacks.”

* **Precision illusion:**

  * 10⁶ packets = 3 attacks.
  * Packet-level → 999,000 TPs → Precision 99.9%.
  * Attack-level → 3 TPs, 1000 FPs → Precision 0.29%.
  * FP count remains since each false alert is an independent wrong event.
## Relevance

* **Part of my research question supported:**

  > We conclude that a suitable area of application for ML-based intrusion detection is most probably anomaly detection. 🔗 [anchor: Motivation]

* **How I can reuse/build on it:**

  * Extends directly to IoT-specific MQTT protocol analysis (Ciklabakkal et al.).
  * Demonstrates the need for **protocol-aware**, hybrid systems, like my SnortML MQTT-Inspector.

* **Limitation/gap exposed:**

  * Lack of realistic datasets, poor generalization, no robust zero-day defense, all core challenges my work addresses.

**Tags:** `ml`, `ids`, `zero-day`, `neural-network`

## My Insight

The study reveals that while neural IDSs show strong results in controlled datasets, they collapse in realistic conditions. Snort’s rule-based precision and ML’s pattern recognition highlight complementary strengths. A hybrid, SnortML-based MQTT Inspector could bridge that gap: combining Snort’s stability and ML’s adaptability for detecting emerging IoT threats.
