# MQTT Inspector for Snort3

A custom MQTT protocol inspector for Snort3 IDS/IPS, developed as part of a thesis project.

## Files

| File | Purpose |
|------|---------|
| `mqtt.h` | Main header: data structures, FlowData class |
| `mqtt.cc` | Main implementation: packet parsing, buffer extraction, event publishing |
| `mqtt_module.h/cc` | Snort3 module: configuration, statistics, alerts |
| `mqtt_paf.h/cc` | Protocol-Aware Flushing: TCP stream reassembly for MQTT framing |
| `mqtt_events.h` | DataBus events for inter-plugin communication |
| `ips_mqtt_topic.cc` | IPS rule option: `mqtt_topic` |
| `ips_mqtt_payload.cc` | IPS rule option: `mqtt_payload` |
| `CMakeLists.txt` | Build configuration |

## Integration with Snort3

### Prerequisites

1. Download Snort3 source (tested with version 3.10.0.0):
   ```bash
   wget https://github.com/snort3/snort3/archive/refs/tags/3.10.0.0.tar.gz
   tar -xzf 3.10.0.0.tar.gz
   cd snort3-3.10.0.0
   ```

2. Install dependencies (macOS):
   ```bash
   brew install pcre2 libdnet hwloc luajit openssl libdaq
   ```

### Installation

1. Copy the mqtt_inspector files into the Snort3 source tree:
   ```bash
   cp -r mqtt_inspector/ /path/to/snort3-3.10.0.0/src/service_inspectors/mqtt/
   ```

2. Register the inspector in the parent CMakeLists.txt:
   ```bash
   # Edit: snort3-3.10.0.0/src/service_inspectors/CMakeLists.txt
   # Add this line (alphabetically with other add_subdirectory calls):
   add_subdirectory(mqtt)
   ```

3. Build Snort3:
   ```bash
   cd snort3-3.10.0.0
   mkdir build && cd build
   cmake ..
   make -j$(nproc)
   ```

4. Verify the MQTT inspector is loaded:
   ```bash
   ./src/snort --list-plugins | grep mqtt
   ```


## Protocol Support

Based on **MQTT 3.1.1 (OASIS Standard, 29 October 2014)**

### Implemented Features

- [x] Variable-length remaining length decoding (Section 2.2.3)
- [x] CONNECT packet parsing with Client ID extraction (Section 3.1)
- [x] PUBLISH packet parsing with topic/payload extraction (Section 3.3)
- [x] QoS level detection (0, 1, 2)
- [x] Protocol-Aware Flushing for TCP stream reassembly
- [x] DataBus event publishing for inter-plugin communication

### IPS Buffers

| Buffer | Description |
|--------|-------------|
| `mqtt_topic` | Topic string from PUBLISH packets |
| `mqtt_payload` | Payload data from PUBLISH packets |
| `mqtt_client_id` | Client ID from CONNECT packets |

## Architecture

```
TCP Stream → MqttSplitter (PAF) → Mqtt::eval() → Buffer Extraction
                                       ↓
                              DataBus Events
                              (MqttPublishEvent, MqttConnectEvent)
```

## References

- MQTT 3.1.1 Specification: http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
- Snort3 Manual: https://snort.org/documents
- Snort3 Source (modbus inspector reference): `src/service_inspectors/modbus/`

## Author

Zhinoo Zobairi - Thesis Project 2025/2026
