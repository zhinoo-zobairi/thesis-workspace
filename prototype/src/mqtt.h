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
    uint16_t flags;
    uint8_t packet_type;
    uint8_t qos;              
    uint16_t packet_id;       
    uint16_t topic_length;    
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

