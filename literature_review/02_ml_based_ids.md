## A Comparison of Neural-Network-Based Intrusion Detection against Signature-Based Detection in IoT Networks


### Problem
- **many papers on ML based ID which doesnt compare the results to a baseline of Signature-Based ID.**
- number of IoT devices in 2022 14.3 billion and in 2023 16.7 and now i searched google in 2025 it is 21.1 billion which exposes a huge attack surface.
- two different types of IDS : anamoly-based (comparing to the variance or mean value of normal situation; not in every attack the behaviour is innormal) and signature-based (patterns and events precisely defined to avoid false alarms). In recent years we use machine learning to etect attacks and learn patterns from the data. Dini et al. showed decision tree performed the best compared to the other seven approaches. a survey in 2021 favored deep learning IDS(at least 2 layers between input and output).
- pitfall number 6 according to Arp et al. is the inappropriate baseline impossible to demonstrate improvements against the state of the art
- only Gray et al has compared a random forest classifier against the Suricata intrusion detection system(but was configured only with a subset of the Emerging Threats Open rule set, which makes the comparison unrealistic)
- Cahyo et al. compares 20 papers published between 2016-2020, which all combined signature-based IDS with anomaly-detection. These hybrid approaches have yet to be adopted in practice.
- **the majority of the publications in the field do not compare their results with a proper baseline.**

### Approach
a comparison study: picked one of the best performing DLIDSs against Snort and conducted an experimental study: replicated a research study that uses a deep neural network model for ID. They observe two different attack scenarios: IoT being the attack target or attack originating from an IoT device(for ecxample for distributed DDoS)
### Dataset / Experiment
Testing the neural network model on a new dataset dropped the accuracy of the neural network to 54%.
### Results
**How does a state-of-the-art DLIDS perform in comparison to a signature-based IDS?** reveal several systematic problems with the used datasets and evaluation methods. a signature-based intrusion detection system with a minimal setup was able to outperform the tested model even under small traffic changes. Couldnt detect zero-day attacks in this experiment.
### Limitations
According to Arp et al 10 pitfalls which frequently occur:
- P1: Sampling bias: data does not represent network traffic
- P6: Inappropriate baseline: compared to very similar approaches not the state of the art
- P7: Inappropriate performance measures: just accuracy is insufficient, precision is important due to high false positive rate: The detailed definition of the performance metrics for the multiclass classification problem is often missing
- P8: Base rate fallacy: accounts for misleading interpretation of results.
- Zola et al. the authors stated that most of the ML-based approaches ignore a key feature of malware: its dynamic nature since malware is constantly evolving. 
- ML-based approaches are the target of attacks themselves: input manipulation, data poisoning, and model inversion
- diversity of the environments and the dynamic behavior of IT infrastructures and services.
- new applications evolve and may initiate new types of traffic. 
-  many benchmark datasets do not adequately represent the real problem of network intrusion detection
### Relevance

- What part of my research question does this paper help with?


- How can I reuse or build on this knowledge?
Some research also addresses IoT-related attacks targeting the MQTT messaging protocol (Ciklabakkal et al.)

- What limitation or gap does this paper reveal that I might solve?


**Tags:** ml, ids, zero-day, neural-network

### My Insight

