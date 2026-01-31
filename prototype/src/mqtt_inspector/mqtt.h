#ifndef MQTT_H
#define MQTT_H

#include <sys/time.h>
#include "flow/flow.h"
#include "framework/counts.h"

struct MqttStats
{
    PegCount sessions;
    PegCount frames;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

struct mqtt_session_data_t //naming inspired by modbus:Data extracted from the current PDU (CURRENT message being processed in this session), Reset for EACH new MQTT message, Named "session" because it's the current "work"
{
    // Phase1, mqtt.hdrflags - Full first byte containing type + flags
    uint8_t hdr_flags;
    // Phase1, mqtt.msgtype - Packet type (1-14)
    uint8_t msg_type;
    // mqtt.dupflag - DUP flag (bit 3 of first byte)
    uint8_t dup_flag;
    // Phase1, mqtt.qos - QoS level (bits 1-2 of first byte)
    uint8_t qos;
    // mqtt.retain - RETAIN flag (bit 0 of first byte)
    uint8_t retain;
    // mqtt.len - Remaining length
    uint32_t remaining_len;
    // Phase1, mqtt.msgid - Message ID (PUBLISH QoS>0, SUBSCRIBE, UNSUBSCRIBE, etc.)
    uint16_t msg_id;

    // === CONNECT packet fields ===
    // mqtt.proto_len
    uint16_t proto_len;
    // mqtt.protoname - pointer to protocol name in packet
    const uint8_t* proto_name;
    // mqtt.ver - Protocol version (3=3.1, 4=3.1.1, 5=5.0)
    uint8_t protocol_version;
    // mqtt.conflags - Connect flags byte
    uint8_t connect_flags;
    // mqtt.conflag.reserved (bit 0)
    uint8_t conflag_reserved;
    // mqtt.conflag.cleansess (bit 1)
    uint8_t conflag_clean_session;
    // mqtt.conflag.willflag (bit 2)
    uint8_t conflag_will_flag;
    // mqtt.conflag.qos - Will QoS (bits 3-4)
    uint8_t conflag_will_qos;
    // mqtt.conflag.retain - Will Retain (bit 5)
    uint8_t conflag_will_retain;
    // mqtt.conflag.passwd (bit 6)
    uint8_t conflag_passwd;
    // mqtt.conflag.uname (bit 7)
    uint8_t conflag_uname;
    // mqtt.kalive - Keep alive timer
    uint16_t keep_alive;
    // mqtt.clientid
    const uint8_t* client_id;
    // mqtt.clientid_len
    uint16_t client_id_len;
    // mqtt.willtopic
    const uint8_t* will_topic;
    // mqtt.willtopic_len
    uint16_t will_topic_len;
    // mqtt.willmsg
    const uint8_t* will_msg;
    // mqtt.willmsg_len
    uint16_t will_msg_len;
    // mqtt.username
    const uint8_t* username;
    // mqtt.username_len
    uint16_t username_len;
    // mqtt.passwd
    const uint8_t* password;
    // mqtt.passwd_len
    uint16_t passwd_len;

    // === CONNACK packet fields ===
    // mqtt.conack.flags
    uint8_t conack_flags;
    // mqtt.conack.flags.sp - Session Present (bit 0)
    uint8_t conack_session_present;
    // mqtt.conack.flags.reserved (bits 1-7)
    uint8_t conack_reserved;
    // mqtt.conack.val - Return code
    uint8_t conack_return_code;

    // === PUBLISH packet fields ===
    // mqtt.topic
    const uint8_t* topic;
    // Phase1, mqtt.topic_len
    uint16_t topic_len;
    // mqtt.msg - Payload
    const uint8_t* payload;
    // mqtt.msg length
    uint32_t payload_len;

    // === SUBSCRIBE packet fields ===
    // mqtt.sub.qos - Requested QoS values (up to 8 topics)
    uint8_t sub_qos[8];
    uint8_t sub_qos_count;

    // === SUBACK packet fields ===
    // mqtt.suback.qos - Granted QoS values (up to 8 topics)
    uint8_t suback_qos[8];
    uint8_t suback_qos_count;
};

struct mqtt_timing_data_t
{
    struct timeval first_pkt_time;
    struct timeval prev_pkt_time;
    uint32_t pkt_count;
    uint32_t failed_auth_count;
    uint32_t failed_auth_window_count;
    struct timeval failed_auth_window_start;
};

class MqttFlowData : public snort::FlowData
{
public:
    MqttFlowData();
    ~MqttFlowData() override;

    static void init();

    void reset()
    {
        memset(&ssn_data, 0, sizeof(ssn_data));
    }

    void update_timing(const struct timeval& pkt_time);
    int64_t get_time_delta_us() const;
    int64_t get_time_relative_us() const;
    void record_auth_failure(const struct timeval& pkt_time);
    float get_failed_auth_per_second(const struct timeval& pkt_time) const;

public:
    static unsigned inspector_id;
    mqtt_session_data_t ssn_data;
    mqtt_timing_data_t timing;
};


extern THREAD_LOCAL MqttStats mqtt_stats;
bool get_buf_mqtt_topic(snort::Packet* p, snort::InspectionBuffer& b);
bool get_buf_mqtt_payload(snort::Packet* p, snort::InspectionBuffer& b);
bool get_buf_mqtt_client_id(snort::Packet* p, snort::InspectionBuffer& b);

#endif