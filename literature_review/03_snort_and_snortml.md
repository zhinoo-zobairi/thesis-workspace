# Evaluation of the machine learning-based intrusion detection system SnortML

### Problem

Rule-based intrusion detection systems cannot detect such a **novel attack** eciently, as the exploit is **unknown** to the victims. Accordingly, the chance that the **set of rules** of known attacks utilized in traditional signature based intrusion detection systems matches the exploit is slim. The report from 2022 shows that more zero-day vulnerabilities were exploited in 2021 than in the years 2018 to 2020 combined. 🔗 [anchor: Motivation] Due to this, CISCO introduced an approach to combine classical intrusion detection structures with machine learning to detect anomalies in network trac aiming to close the security gap for zero-day exploits.

### Approach
> Train small → refine & analyze → tune → scale up → test full

| Step | Action                                            | Purpose                                        |
| ---- | ------------------------------------------------- | ---------------------------------------------- |
| 1    | Train model on Thursday subset                    | Establish baseline                             |
| 2    | Modify model + create synthetic traffic           | Test on self-similar data                      |
| 3    | Compare `http_inspector` vs. `snort_ml_inspector` | Analyze packet coverage and inspection overlap |
| 4    | Tune parameters on undersampled Thursday subset   | Balance classes and improve model quality      |
| 5    | Evaluate best model on full dataset               | Measure real-world generalization              |

> In this thesis an evaluation will be performed.

- The work is not purely theoretical, it will test and measure something = **This thesis includes an empirical assessment of how well SnortML performs as an intrusion detection mechanism.**
**Criteria for evaluation:**
    - how well SnortML performs as a detection system with respect to *known attacks* and *new attacks*.
    **by analysing a given offline network PCAP:**

    *“offline”* means they are not testing Snort live in a running network. Instead, they use pre-recorded traffic stored in **PCAP** files (PCAP stands for **Packet Capture**: libpcap (API) → lets programs capture packets live & .pcap file (format) → stores those captured packets for offline analysis.)
    **replaying that recorded traffic through SnortML and observing how it classifies each packet (benign or malicious).**


- Using **precision** or **recall** alone can give a distorted picture of a model’s performance.
If the model detects only one attack correctly and labels everything else as normal, **precision** looks perfect but **recall** is poor.
If it marks everything as malicious, **recall** becomes perfect but **precision** collapses due to false alarms.

To balance these two, we use the **F-score**, the weighted harmonic mean of precision (P) and recall (R):

$
    [
    F_\beta = (1 + \beta^2)\frac{P \times R}{\beta^2 P + R}
    ]
$

The parameter **β** controls whether recall or precision is emphasized.
When **β = 1**, both are equally important — this is the **F1-score**:
$
    [
    F_1 = 2\frac{P \times R}{P + R}
    ]
$

This thesis uses the **F1-score** to measure SnortML’s detection performance.

### Dataset / Experiment

### Results


### Limitations


### Relevance

**Tags:** 

### My Insight

