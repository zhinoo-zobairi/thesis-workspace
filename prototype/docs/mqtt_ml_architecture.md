## Attack-to-Field Mapping

| Attack | Critical Fields |
|--------|----------------|
| **Flooding DoS** | `time_delta`, `tcp.flags`, packet counts, `ip.src` |
| **SlowITe** | `mqtt.kalive`, `time_delta`, connection duration |
| **Brute-Force** | `mqtt.conack.val`, `mqtt.clientid`, connection attempts per IP |
| **Malformed** | `mqtt.len`, `mqtt.msgtype`, `mqtt.protoname`, validation errors |
| **Malaria DoS** | `mqtt.qos`, `mqtt.msgtype`, message rates |

> Why care about TCP flags (`p->ptrs.tcph->th_flags`) for Flooding DoS?

> Attacker sends many SYN packets without completing handshake → exhausts server's half-open connection table. Many SYN with no corresponding ACK is a sign for the ML model

> Why `mqtt.qos` matters for SlowITe attack?

> 
>**QoS 0**: *Fire-and-forget* (no acknowledgment)
>
>**QoS 1**: *At-least-once* (requires PUBACK)
>
>**QoS 2**: *Exactly-once* (requires 4-way handshake: PUBLISH→PUBREC→PUBREL→PUBCOMP)
>
>**The attack**:
>
>Client sends PUBLISH with QoS 2
>
>Broker responds with PUBREC, waits for PUBREL
>
>Attacker never sends PUBREL → broker keeps session state open indefinitely
>
>Repeat → exhaust broker's memory/connection pool

---

## Architecture for Production-Ready Real-Time Detection
1. Snort starts
2. Reads snort.lua
3. Sees "mqtt = { }" → Creates MqttModule → Creates Mqtt inspector
4. Sees "mqtt_ml = {...}" → Creates MqttMLModule → Creates MqttML inspector
5. `MqttML::configure()` subscribes to DataBus (Each inspector has its own configure() method, they all inherit from inspector.cc, which does nothing and return true but it can be overwritten for different purposes)
    - What is **DataBus**?
    - DataBus is Snort3's **publish-subscribe (pub/sub) messaging system**.
    ```
    Snort startup
    │
    ├── Load all inspector modules
    ├── Create inspector instances (mqtt_ctor, mqtt_ml_ctor called)
    ├── Call configure() on each inspector   ← HERE
    │       • MqttML::configure() → subscribes to DataBus
    │       • Mqtt::configure() → does nothing (default)
    │
    └── Start packet processing loop
            └── For each packet: call eval()
    ```

6. Packet arrives on port 1883 → `Mqtt::eval()` called → publishes MqttFeatureEvent
    - This is done via the binder in snort.lua:
    ````
    binder = {
    { when = { proto = 'tcp', ports = '1883' }, 
      use = { type = 'mqtt' } }
    }
    ````
    - **DAQ** (Data Acquisition) captures packet on **port 1883**
    - **Stream** (TCP reassembly) builds **complete PDU**
    - **Binder** sees port **1883** → **assigns mqtt as the service inspector**
    - Snort calls **Mqtt::eval(p)** with the packet
    - **eval() parses**, then **publishes MqttFeatureEvent**
    - **DataBus** routes event to all subscribers (including **MqttFeatureHandler**)
7. `MqttFeatureHandler::handle()` receives event → runs ML

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
│  │  mqtt inspector │────▶│  MqttFeatureEvent│                   │
│  │                 │     │  (via DataBus)   │                   │
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
#### The handler IS how DataBus routes to the ML inspector. The handler is the receiving end of the pub/sub pattern. It's like subscribing to a newsletter: you need a mailbox (handler) to receive it.
```
Mqtt::eval()  ─────publish(MqttFeatureEvent)───→  DataBus
                                                     │
                                                     │ routes to subscribers
                                                     ▼
                                           MqttFeatureHandler::handle()
                                           (inside mqtt_ml inspector)
```


#### Are MqttModule and MqttMLModule two independent inspectors, like modbus and mqtt are independent? 

>YES, They are two separate, independent inspectors that communicate via DataBus:

```
┌─────────────────────────────┐       ┌─────────────────────────────┐
│  modbus                     │       │  mqtt                       │
│  (independent inspector)    │       │  (independent inspector)    │
│  - Parses Modbus protocol   │       │ - Parses MQTT protocol      │
│  - No connection to others  │       │ - Publishes MqttFeatureEvent│
└─────────────────────────────┘       └──────────────┬──────────────┘
                                                     │
                                                     │ DataBus
                                                     ▼
                                      ┌─────────────────────────────┐
                                      │  mqtt_ml                    │
                                      │  (independent inspector)    │
                                      │  - Subscribes to events     │
                                      │  - Runs ML inference        │
                                      └─────────────────────────────┘
```
**Key points:**

| Aspect | mqtt | mqtt_ml |
|--------|------|---------|
| Can run alone? | ✅ Yes | ✅ Yes (but receives no events) |
| Depends on other? | No | Needs mqtt to publish events |
| Registered separately | `sin_mqtt[]` | `sin_mqtt_ml[]` |
| Configured separately | `mqtt = { }` | `mqtt_ml = { threshold = 0.5 }` |

**Why this design?**
- **Modularity** - mqtt_ml can be disabled without touching mqtt
- **Separation of concerns** - Parsing logic ≠ ML logic
- **Reusability** - Other inspectors could also subscribe to MqttFeatureEvent
- **Snort convention** - Same pattern as `http_inspect` → `snort_ml`
---
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

#### Timing Logic Explained Step-by-Step

```cpp
void MqttFlowData::update_timing(const struct timeval& pkt_time)
{
    if (timing.pkt_count == 0) {           // Is this the FIRST packet?
        timing.first_pkt_time = pkt_time;  // Remember when flow started
    }
    timing.prev_pkt_time = pkt_time;       // ALWAYS update "previous"
    timing.pkt_count++;                    // Increment counter
}
```

**Example with 3 packets:**

| Packet # | `pkt_time` | `first_pkt_time` | `prev_pkt_time` | `pkt_count` |
|----------|------------|------------------|-----------------|-------------|
| Before any | - | 0 | 0 | 0 |
| 1st | 10:00:00.000 | **10:00:00.000** | 10:00:00.000 | 1 |
| 2nd | 10:00:00.500 | 10:00:00.000 | **10:00:00.500** | 2 |
| 3rd | 10:00:01.200 | 10:00:00.000 | **10:00:01.200** | 3 |

**Notice:**
- `first_pkt_time` is set ONLY on the first packet, never changes
- `prev_pkt_time` is updated for EVERY packet (it tracks "current" packet's time)

**Then `get_time_delta_us()` calculates:**
```cpp
int64_t MqttFlowData::get_time_delta_us() const
{
    if (timing.pkt_count < 2)
        return 0;  // Can't compute delta with only 1 packet
    
    // prev_pkt_time - first_pkt_time = time since flow started
    return (timing.prev_pkt_time.tv_sec - timing.first_pkt_time.tv_sec) * 1000000LL +
           (timing.prev_pkt_time.tv_usec - timing.first_pkt_time.tv_usec);
}
```

**For packet #3:**
```
prev_pkt_time  = 10:00:01.200  (current packet)
first_pkt_time = 10:00:00.000  (first packet)

delta = (1 - 0) * 1,000,000 + (200,000 - 0)
      = 1,000,000 + 200,000
      = 1,200,000 microseconds
      = 1.2 seconds since flow started
```

**Why do we call it `prev_pkt_time` if it's the current packet?**
It's named for what it will be *after* `eval()` returns - when the *next* packet arrives, this will be the "previous" packet's time. Perhaps `last_pkt_time` would be a clearer name!

````
┌─────────────────────────────────────────────────────────────────────┐
│  mqtt.h - Structure Definitions                                     │
│                                                                     │
│  struct mqtt_timing_data_t {                                        │
│      uint32_t failed_auth_window_count;  // Member variable         │
│      struct timeval failed_auth_window_start;                       │
│      ...                                                            │
│  };                                                                 │
│                                                                     │
│  class MqttFlowData {                                               │
│      mqtt_timing_data_t timing;  // Contains the struct above       │
│  };                                                                 │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  MqttFlowData() constructor                                         │
│      memset(&timing, 0, sizeof(timing));  // All fields = 0         │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Mqtt::eval(Packet* p)                                              │
│                                                                     │
│  1. pkt_time = p->pkth->ts;  // Get timestamp from packet           │
│                                                                     │
│  2. if (CONNACK && return_code != 0)                                │
│         mfd->record_auth_failure(pkt_time);                         │
│         └── timing.failed_auth_window_count++ (incremented here)    │
│                                                                     │
│  3. fe.failed_auth_per_second = mfd->get_failed_auth_per_second();  │
│         └── reads timing.failed_auth_window_count                   │
│         └── calculates: count * 1000000 / elapsed_time              │
└─────────────────────────────────────────────────────────────────────┘
````
---

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
### How is the training ?
What we'll do with real data:
```
python mqtt_feature_extractor.py \
    --normal_dir data/normal \
    --attack_dir data/attack \
    --output mqtt_features.csv
# Result: thousands of samples

python train_mqtt_model.py \
    --data mqtt_features.csv \
    --output mqtt_model.tflite \
    --model_type autoencoder
# Result: trained model
```

### The trained model is saved as a .tflite file. It contains:

- The learned weights (patterns it learned)
- The architecture (how to process the 28 inputs)

When Snort loads this file, it can make predictions without re-training.

- Training (once):
    - PCAPs → 28 features → Model learns patterns → Save to mqtt_model.tflite

- Inference (every packet):
    - Live packet → 28 features → Load mqtt_model.tflite → "normal" or "attack"