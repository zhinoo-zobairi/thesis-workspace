## Attack-to-Field Mapping

| Attack | Critical Fields |
|--------|----------------|
| **Flooding DoS** | `time_delta`, `tcp.flags`, packet counts, `ip.src` |
| **SlowITe** | `mqtt.kalive`, `time_delta`, connection duration |
| **Brute-Force** | `mqtt.conack.val`, `mqtt.clientid`, connection attempts per IP |
| **Malformed** | `mqtt.len`, `mqtt.msgtype`, `mqtt.protoname`, validation errors |
| **Malaria DoS** | `mqtt.qos`, `mqtt.msgtype`, message rates |

---

## Architecture for Production-Ready Real-Time Detection

```
                    REAL-TIME PIPELINE
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   Packet                                                        │
│     │                                                           │
│     ▼                                                           │
│  ┌─────────────────┐                                            │
│  │  stream_tcp     │  TCP reassembly                            │
│  └────────┬────────┘                                            │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐     ┌──────────────────┐                   │
│  │  mqtt inspector │────▶│  MqttFeatureEvent │                  │
│  │                 │     │  (via DataBus)    │                  │
│  │ • Parse packet  │     └─────────┬────────┘                   │
│  │ • Extract fields│               │                            │
│  │ • Calc timing   │               ▼                            │
│  │ • Update stats  │     ┌──────────────────┐                   │
│  └─────────────────┘     │  mqtt_ml handler │                   │ 
│                          │                  │                   │
│                          │ • Receive event  │                   │
│                          │ • Build feature  │                   │
│                          │   vector         │                   │ 
│                          │ • Run inference  │                   │
│                          │ • Score > thresh │                   │
│                          │   → ALERT        │                   │ 
│                          └──────────────────┘                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘


MQTT Inspector                    DataBus                    ML Handler
      │                              │                            │
      │  parse_connect_packet()      │                            │
      │  ─────────────────────▶      │                            │
      │                              │                            │
      │  MqttConnectEvent event(...) │                            │
      │  ─────────────────────▶      │                            │
      │                              │                            │
      │  DataBus::publish(event)     │                            │
      │  ───────────────────────────▶│                            │
      │                              │  handler->handle(event)    │
      │                              │  ────────────────────────▶ │
      │                              │                            │
      │                              │           event.get_client_id()
      │                              │           (ML uses this)   │
```
## Field Extraction

Here's what we have vs. what we need:

| Field | Source | Status |
|-------|--------|--------|
| **Timestamps** | `p->pkth->ts` | Snort provides |
| **Time Delta** | Should be calculated from FlowData | 🔧 I implement it |
| **TCP Flags** | `p->ptrs.tcph->th_flags` | Snort provides |
| **TCP Stream** | `p->flow` (pointer = ID) | Snort provides |
| **TCP Length** | `p->dsize` | Snort provides |
| **IP Src/Dst** | `p->ptrs.ip_api.get_src/dst()` | Snort provides |
| **Ports** | `p->ptrs.sp`, `p->ptrs.dp` | Snort provides |


## The role of `mqtt_events.cc` 
- When `mqtt.cc` parses a packet, it puts the extracted data into one of **these event classes** and **publishes** it. Any other component can subscribe and receive this data.
- It defines data containers that carry extracted MQTT data:
````cc
// 1. Event type identifiers
struct MqttEventIds
{
    enum : unsigned
    {
        MQTT_PUBLISH,   // Event type 0
        MQTT_CONNECT,   // Event type 1
        MAX
    };
};

// 2. Publisher registration key
const snort::PubKey mqtt_pub_key { "mqtt", MqttEventIds::MAX };

// 3. Data container for PUBLISH packets
class MqttPublishEvent : public snort::DataEvent
{
    // Holds: topic, topic_length, payload, payload_length, qos
};

// 4. Data container for CONNECT packets
class MqttConnectEvent : public snort::DataEvent
{
    // Holds: client_id, client_id_length
    // MISSING: keep_alive, connect_flags, protocol_version, etc.
};
````
## The role of Handler Class
- It's as a listener that waits for specific events:
```
┌──────────────┐      ┌──────────────┐      ┌─────────────┐        ┌──────────────┐
│    mqtt      │      │   DataBus    │      │   Handler   │        │   ML Engine  │
│  inspector   │      │  (message    │      │   (Bridge)  │        │  (inference) │
│              │      │   router)    │      │             │        │              │
│ Extracts     │──────▶ Routes event │──────▶ Receives    │──────▶ Runs model     │
│ MQTT data    │event │ to all       │event │ event,      │features│ Returns      │
│              │      │ subscribers  │      │ extracts    │        │ score        │
│              │      │              │      │ features    │        │              │
└──────────────┘      └──────────────┘      └─────────────┘        └──────────────┘
                                                   │
                                                   ▼
                                            If score > threshold
                                                 ALERT!
```
- mqtt inspector = Producer (publishes events)
- DataBus = Message router (delivers events to subscribers)
- Handler = Consumer (receives events, processes them)
- ML Engine = The actual neural network/model

The Handler is the "bridge" because it:

1. Receives generic DataEvent
2. Casts it to specific type (MqttConnectEvent)
3. Extracts features the ML model needs
4. Calls the ML engine
5. Decides whether to alert

---

## Feature Importance Analysis for MQTT Attack Detection

To prioritize which MQTT features are most relevant for attack detection, we perform a **feature importance analysis** using a Random Forest classifier.  

### Concept

A Random Forest is an ensemble of decision trees. Each tree learns to separate attacks (`label=1`) from benign traffic (`label=0`) by splitting on features that reduce uncertainty (measured as **Gini impurity** or **entropy**).  

**Feature importance** quantifies how much each feature contributes to reducing uncertainty across all trees:  

- **High importance** → the feature is critical for distinguishing attacks from normal traffic  
- **Low importance** → the feature contributes little to prediction and can be deprioritized  

This allows us to focus implementation efforts on the **top features** while avoiding unnecessary overhead.

### Workflow

1. **Load dataset**: All features from MqttSet are loaded, with the `label` column as the target.  
2. **Train model**: A Random Forest classifier is trained on all features.  
3. **Compute importance**: For each feature, the total decrease in impurity across all trees is calculated and normalized.  
4. **Rank features**: Features are sorted by importance to identify the top contributors to attack detection.  

**Example outcome (top features):**

| Feature         | Importance |
|-----------------|------------|
| mqtt.kalive     | 0.31       |
| time_delta      | 0.22       |
| mqtt.conack.val | 0.18       |
| tcp.len         | 0.11       |
| mqtt.qos        | 0.03       |

This analysis informs **which fields the MQTT inspector should prioritize extracting**, ensuring efficient and effective ML-based detection.

````py
#!/usr/bin/env python3
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import warnings
import numpy as np
warnings.filterwarnings('ignore')

# Load data
df = pd.read_csv('train70_reduced.csv')
print(f"Dataset: {len(df)} rows, {len(df.columns)} columns")
print(f"\nLabels: {df['target'].value_counts().to_dict()}")

# Prepare features and target
X = df.drop('target', axis=1)
y = LabelEncoder().fit_transform(df['target'])

# Handle non-numeric columns (convert hex strings and objects to numeric)
for col in X.columns:
    if X[col].dtype == 'object':
        # Try to convert hex strings like '0x00000018' to integers
        try:
            X[col] = X[col].apply(lambda x: int(x, 16) if isinstance(x, str) and x.startswith('0x') else x)
        except:
            pass
        # If still object type, convert to categorical codes
        if X[col].dtype == 'object':
            X[col] = pd.Categorical(X[col]).codes

# Convert all to numeric, coerce errors to NaN
X = X.apply(pd.to_numeric, errors='coerce')

# Replace infinity with NaN, then fill NaN with -1
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(-1)

# Ensure float32 range
X = X.clip(-1e30, 1e30)

# Train Random Forest
print("\nTraining RandomForest for feature importance...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X, y)

# Get feature importance
importance = pd.DataFrame({
    'feature': X.columns,
    'importance': rf.feature_importances_
}).sort_values('importance', ascending=False)

print("\n" + "="*60)
print("MQTT FEATURE IMPORTANCE (Top 20)")
print("="*60)
for idx, row in importance.head(20).iterrows():
    bar = "#" * int(row['importance'] * 100)
    print(f"{row['feature']:35} {row['importance']:.4f} {bar}")

print("\n" + "="*60)
print("BOTTOM 10 (Likely Not Needed)")
print("="*60)
for idx, row in importance.tail(10).iterrows():
    print(f"{row['feature']:35} {row['importance']:.4f}")

# Save to CSV
importance.to_csv('feature_importance_results.csv', index=False)
print("\nResults saved to feature_importance_results.csv")
````
---

## TASK CHECKLIST 📋 
````
[ ] Step 1: Extend mqtt.cc to extract additional fields
    [ ] Parse msg_id from PUBLISH/SUBSCRIBE
    [ ] Parse hdr_flags (first byte)
    [ ] Parse keep_alive from CONNECT
    [ ] Parse conack_return from CONNACK
    [ ] Parse connect_flags from CONNECT
    [ ] Parse protocol_version from CONNECT

[ ] Step 2: Implement MqttFlowData for timing
    [ ] Create class with timestamp tracking
    [ ] Register with Snort's flow system
    [ ] Calculate time_delta and time_relative

[ ] Step 3: Create MqttFeatureEvent
    [ ] Define all feature fields
    [ ] Add getters for ML handler

[ ] Step 4: Create mqtt_ml inspector
    [ ] Set up directory structure
    [ ] Create handler subscribing to MQTT events
    [ ] Implement feature vector construction
    [ ] Integrate ML inference library
    [ ] Generate alerts on detection

[ ] Step 5: Train and export model
    [ ] Train on MqttSet dataset
    [ ] Export to TFLite/ONNX
    [ ] Test model accuracy

[ ] Step 6: Integration testing
    [ ] Test with mqtt_snort.pcap
    [ ] Test with attack samples
    [ ] Performance benchmarking
````
---

## **All MQTT Fields Extracted:**

| Wireshark Field | Structure Field | Packet Type |
|-----------------|-----------------|-------------|
| `mqtt.hdrflags` | `hdr_flags` | ALL |
| `mqtt.msgtype` | `msg_type` | ALL |
| `mqtt.dupflag` | `dup_flag` | ALL |
| `mqtt.qos` | `qos` | ALL |
| `mqtt.retain` | `retain` | ALL |
| `mqtt.len` | `remaining_len` | ALL |
| `mqtt.msgid` | `msg_id` | PUBLISH/SUB/UNSUB/ACKs |
| `mqtt.proto_len` | `proto_len` | CONNECT |
| `mqtt.protoname` | `proto_name` | CONNECT |
| `mqtt.ver` | `protocol_version` | CONNECT |
| `mqtt.conflags` | `connect_flags` | CONNECT |
| `mqtt.conflag.reserved` | `conflag_reserved` | CONNECT |
| `mqtt.conflag.cleansess` | `conflag_clean_session` | CONNECT |
| `mqtt.conflag.willflag` | `conflag_will_flag` | CONNECT |
| `mqtt.conflag.qos` | `conflag_will_qos` | CONNECT |
| `mqtt.conflag.retain` | `conflag_will_retain` | CONNECT |
| `mqtt.conflag.passwd` | `conflag_passwd` | CONNECT |
| `mqtt.conflag.uname` | `conflag_uname` | CONNECT |
| `mqtt.kalive` | `keep_alive` | CONNECT |
| `mqtt.clientid` | `client_id` | CONNECT |
| `mqtt.clientid_len` | `client_id_len` | CONNECT |
| `mqtt.willtopic` | `will_topic` | CONNECT |
| `mqtt.willtopic_len` | `will_topic_len` | CONNECT |
| `mqtt.willmsg` | `will_msg` | CONNECT |
| `mqtt.willmsg_len` | `will_msg_len` | CONNECT |
| `mqtt.username` | `username` | CONNECT |
| `mqtt.username_len` | `username_len` | CONNECT |
| `mqtt.passwd` | `password` | CONNECT |
| `mqtt.passwd_len` | `passwd_len` | CONNECT |
| `mqtt.conack.flags` | `conack_flags` | CONNACK |
| `mqtt.conack.flags.sp` | `conack_session_present` | CONNACK |
| `mqtt.conack.flags.reserved` | `conack_reserved` | CONNACK |
| `mqtt.conack.val` | `conack_return_code` | CONNACK |
| `mqtt.topic` | `topic` | PUBLISH |
| `mqtt.topic_len` | `topic_len` | PUBLISH |
| `mqtt.msg` | `payload` | PUBLISH |
| `mqtt.sub.qos` | `sub_qos[8]` | SUBSCRIBE |
| `mqtt.suback.qos` | `suback_qos[8]` | SUBACK |

### **Timing & Brute Force Detection:**

| Feature | Method/Field | Purpose |
|---------|--------------|---------|
| `time_delta` | `get_time_delta_us()` | Time since flow start (μs) |
| `time_relative` | `get_time_relative_us()` | Time since first packet (μs) |
| `failed_auth_per_second` | `get_failed_auth_per_second()` | Brute force detection rate |
| `pkt_count` | `timing.pkt_count` | Packets in this flow |
| `failed_auth_count` | `timing.failed_auth_count` | Total failed auths |

### **Parsers Added:**

- `parse_fixed_header()` - Extracts msg_type, qos, dup, retain, remaining_len
- `parse_connect_packet()` - Full CONNECT parsing including Will, Username, Password
- `parse_connack_packet()` - Session present flag and return code
- `parse_publish_packet()` - Topic, Message ID, Payload
- `parse_subscribe_packet()` - Message ID and requested QoS values
- `parse_suback_packet()` - Message ID and granted QoS values
- `parse_unsubscribe_packet()` - Message ID
- `parse_ack_packet()` - Message ID for PUBACK/PUBREC/PUBREL/PUBCOMP/UNSUBACK


---
## `session_data_t` Vs. `MqttFlowData`?
````
┌─────────────────────────────────────────────────────────┐
│  mqtt_session_data_t                                    │
│  ════════════════════                                   │
│  • Holds fields PARSED from CURRENT message             │
│  • Reset for EACH new MQTT message                      │
│  • Example: msg_type=3, topic="sensors/temp", qos=1     │
│  • Named "session" because it's the current "work"      │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  MqttFlowData (extends FlowData)                        │
│  ═══════════════════════════════                        │
│  • Persists across ALL messages in one TCP connection   │
│  • Snort manages its lifetime automatically             │
│  • Contains: ssn_data + timing counters                 │
│  • Named "Flow" because it lives for the entire flow    │
└─────────────────────────────────────────────────────────┘
````
### Timeline of ONE MQTT Message Processing
```
┌────────────────────────────────────────────────────────────────┐
│  1. PUBLISH arrives                                            │
│     │ eval(Packet* p)                                          │
│  2. mfd->reset()  ← Clears old data                            │
│     │ if case 3:                                               │
│  3. parse_publish_packet() ← Fill ssn_data with new values     │
│     │                        topic="sensors/temp"              │
│     │                        qos=1                             │
│     │                        msg_id=42                         │
│     │                                                          │
│  4. ══════════ USE THE DATA HERE ══════════                    │
│     │  • Publish event to DataBus (for ML handler)             │
│     │  • IPS rules can match against topic/payload             │
│     │  • Detection engine runs                                 │
│     │                                                          │
│  5. eval() returns                                             │
│     │                                                          │
│  6. Next message arrives → Go to step 1                        │
└────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  TCP Connection #1                                                  │
│  ════════════════                                                   │
│                                                                     │
│  [SYN] ──────────────────────────────────────────────────── [FIN]   │
│         │                                                     │     │
│         │  MQTT Messages (no delimiters, length-prefixed):    │     │
│         │                                                     │     │
│         │  CONNECT → CONNACK → PUBLISH → PUBACK → DISCONNECT  │     │
│         │     │         │         │         │         │       │     │
│         │     ▼         ▼         ▼         ▼         ▼       │     │
│         │  [parse]   [parse]   [parse]   [parse]   [parse]    │     │
│         │  [use]     [use]     [use]     [use]     [use]      │     │
│         │  [reset]   [reset]   [reset]   [reset]   [reset]    │     │
│         │                                                     │     │
│         └─────────────────────────────────────────────────────┘     │
│                                                                     │
│  MqttFlowData (lives entire connection):                            │
│  ├── ssn_data: current message fields (reused, not destroyed)       │
│  └── timing: accumulated across all messages                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Flow in networking = A TCP connection from start to finish (SYN → FIN)

```
Client ──────── TCP Connection (FLOW) ────────▶ Broker

   CONNECT ──▶  [session_data filled, then reset]
   CONNACK ◀──  [session_data filled, then reset]  
   PUBLISH ──▶  [session_data filled, then reset]
   PUBACK  ◀──  [session_data filled, then reset]
   ...
   DISCONNECT   [FlowData destroyed when connection ends]
```

### What TCP Flow Looks Like vs What MQTT Inspector Sees

```
TCP:    SYN ─────────────────────────────────────────────── FIN
                │                                       │
MQTT:        CONNECT  CONNACK  PUBLISH  PUBACK    DISCONNECT
              0ms      50ms     120ms    180ms      200ms
                                                      │
                                          prev_pkt_time = 200ms
                                          (last MQTT message)
```

### **The extracted Timing Fields in a Flow:**
#### (Our timing only tracks MQTT message timestamps, not TCP control packets.)
| Field | Meaning | ML Use |
|-------|---------|--------|
| `first_pkt_time` | When first MQTT message arrived in this flow, 0ms | Baseline for time_relative |
| `prev_pkt_time` | When previous message arrived | Used to calculate time_delta |
| `pkt_count` | Number of MQTT messages in this flow | Flow behavior pattern |
| `time_relative` | `current_time - first_pkt_time` | How long this flow has been active |
| `time_delta` | `current_time - prev_pkt_time` | Gap between messages |
| `failed_auth_per_second` | Auth failures / time window | Brute force detection |

---