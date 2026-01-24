#ifndef MQTT_H
#define MQTT_H

#include "flow/flow.h"
#include "framework/counts.h"

struct MqttStats
{
    PegCount sessions;
    PegCount frames;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

struct mqtt_session_data_t
{
    // Existing fields
    uint16_t flags;
    uint8_t packet_type;
    uint8_t qos;              
    uint16_t packet_id;       
    uint16_t topic_length;
    
    // New fields for ML feature extraction (Step 1)
    uint8_t hdr_flags;        // Full first byte: bits 7-4 = type, bits 3-0 = flags (2.22% importance)
    uint16_t msg_id;          // Message ID from PUBLISH QoS>0, SUBSCRIBE, UNSUBSCRIBE (22.79% importance)
    uint16_t keep_alive;      // Keep-alive interval from CONNECT in seconds (0.47% importance)
    uint8_t conack_return;    // Return code from CONNACK: 0=accepted, 1-5=error (0.71% importance)
    uint8_t connect_flags;    // Connect flags byte from CONNECT (0.19% importance)
    uint8_t protocol_version; // Protocol version: 3=3.1, 4=3.1.1, 5=5.0 (0.23% importance)
};

class MqttFlowData : public snort::FlowData
{
public:
    MqttFlowData();
    ~MqttFlowData() override;

    static void init();

    void reset()
    {
        ssn_data.packet_type = ssn_data.packet_id = 0;
        ssn_data.flags = ssn_data.qos = ssn_data.topic_length = 0;
        ssn_data.hdr_flags = 0;
        ssn_data.msg_id = 0;
        ssn_data.keep_alive = 0;
        ssn_data.conack_return = 0;
        ssn_data.connect_flags = 0;
        ssn_data.protocol_version = 0;
    }

public:
    static unsigned inspector_id;
    mqtt_session_data_t ssn_data;
};


extern THREAD_LOCAL MqttStats mqtt_stats;
bool get_buf_mqtt_topic(snort::Packet* p, snort::InspectionBuffer& b);
bool get_buf_mqtt_payload(snort::Packet* p, snort::InspectionBuffer& b);
bool get_buf_mqtt_client_id(snort::Packet* p, snort::InspectionBuffer& b);

#endif

