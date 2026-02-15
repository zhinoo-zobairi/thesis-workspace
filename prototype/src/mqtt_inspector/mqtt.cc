#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt.h"

#include <cstring>
#include <sys/time.h>

#include "detection/detection_engine.h"
#include "framework/data_bus.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "mqtt_events.h"
#include "mqtt_module.h"
#include "mqtt_paf.h"

using namespace snort;

THREAD_LOCAL MqttStats mqtt_stats;

// Indices in the buffer array exposed by InspectApi
// Must remain synchronized with mqtt_bufs
enum MqttBufId
{
    MQTT_TOPIC_BUFID = 1,
    MQTT_PAYLOAD_BUFID,
    MQTT_CLIENT_ID_BUFID
};

// Helper function - parse PUBLISH packet header and return offset to variable header
static int parse_mqtt_publish_header(Packet* p, uint8_t* packet_type, uint8_t* qos)
{
    if (!p->is_full_pdu() || p->dsize < 2)
        return -1;
    
    // Extract type and QoS from first byte
    uint8_t first_byte = p->data[0];
    *packet_type = first_byte >> 4; //0x30 (binary 00110000) >> 4 = 0x03 (binary 00000011) = PUBLISH and since it is a pointer, we dereference to put a value inside it
    *qos = (first_byte >> 1) & 0x03; // QoS is a 2-bit value, on bits 1 and 2, I want them as a normal number 0–3. 0x03 means keep only the lowest two bits, zero out everything else.
    
    // Check if PUBLISH
    if (*packet_type != 3)
        return -1;
    
    // Skip remaining length bytes (1-4 bytes with bit 7 = continuation flag)
    int offset = 1;
    while (offset < 5 && offset < p->dsize) { // Remaining Length can be at most 4 bytes and it starts at index 1 and do not read past the end of the buffer Snort gave us
        if ((p->data[offset++] & 0x80) == 0) // & 0x80 checks the top bit (bit 7). If it’s 0, this is the last Remaining Length byte → stop. If it’s 1, more bytes follow → continue
            break;  // Last length byte
    }
    
    return offset;  // Points to start of variable header
}

bool get_buf_mqtt_topic(Packet* p, InspectionBuffer& b)
{
    uint8_t packet_type, qos;
    int offset = parse_mqtt_publish_header(p, &packet_type, &qos);
    if (offset < 0)
        return false;
    
    // Read topic length (2 bytes, big-endian)
    if (offset + 2 > p->dsize)
        return false;
    
    uint16_t topic_len = (p->data[offset] << 8) | p->data[offset + 1];
    offset += 2;
    
    // Validate and set buffer
    if (offset + topic_len > p->dsize)
        return false;
    
    b.data = p->data + offset;
    b.len = topic_len;
    return true;
}

bool get_buf_mqtt_payload(Packet* p, InspectionBuffer& b)
{
    uint8_t packet_type, qos;
    int offset = parse_mqtt_publish_header(p, &packet_type, &qos);
    if (offset < 0)
        return false;
    
    // Read and skip topic length
    if (offset + 2 > p->dsize)
        return false;
    
    uint16_t topic_len = (p->data[offset] << 8) | p->data[offset + 1];
    offset += 2 + topic_len;
    
    // Skip packet ID if QoS > 0
    if (qos > 0)
        offset += 2;
    
    // Validate and set buffer to remaining bytes
    if (offset >= p->dsize)
        return false;
    
    b.data = p->data + offset;
    b.len = p->dsize - offset;
    return true;
}

bool get_buf_mqtt_client_id(Packet* p, InspectionBuffer& b)
{
    // 1. Safety check
    if (!p->is_full_pdu() || p->dsize < 2)
        return false;
    
    // 2. Parse packet type (must be CONNECT = 1)
    uint8_t packet_type = p->data[0] >> 4; // If we didn't shift right by 4, and the byte was 0001 0000, the value would be 16 instead of 1.
    if (packet_type != 1) // And we had to write `if (packet_type != 16)` here
        return false;
    
    // 3. Parse and skip remaining length bytes (1-4 bytes with bit 7 = continuation flag)
    int offset = 1;
    while (offset < 5 && offset < p->dsize) {
        if ((p->data[offset++] & 0x80) == 0){ // "Is bit 7 zero?": Here we mask the 7th bit as continuation flag with 1000 0000 (0x80)
            break; // keeping only bit 7 and zeroing out bits 0-6, if result of the AND operation is 0, it means the continuation flag was 0 and it was the last byte
        }
    }
    
    // 4. Skip Protocol Name (2-byte length + string "MQTT")
    if (offset + 2 > p->dsize)
        return false;
    //  shift-and-OR pattern:
    uint16_t proto_len = (p->data[offset] << 8) | p->data[offset + 1]; // For the number 4: MSB occupying the first memory place: holds the big place values but they're all zero, no contribution – LSB occupying the first memory place: holds the small place values and the 4 bit is set, this is where the actual value lives. So even though MSB is "most significant" in terms of position/weight, for small numbers like 4, all the actual value is in the LSB!
    offset += 2 + proto_len;
    
    // 5. Skip Version (1 byte) + Connect Flags (1 byte) + Keep Alive (2 bytes)
    offset += 4;
    
    // 6. Read Client ID Length
    if (offset + 2 > p->dsize)
        return false;
    //  shift-and-OR pattern:
    uint16_t client_id_len = (p->data[offset] << 8) | p->data[offset + 1];
    offset += 2;
    
    // 7. Handle empty client ID (length = 0)
    //    This is valid MQTT - broker assigns ID. No buffer to extract.
    if (client_id_len == 0)
        return false;
    
    // 8. Validate and set buffer
    if (offset + client_id_len > p->dsize)
        return false;
    
    b.data = p->data + offset;
    b.len = client_id_len;
    return true;
}

//-------------------------------------------------------------------------
// MQTT packet parsing functions
//-------------------------------------------------------------------------

static int skip_remaining_length(const uint8_t* data, uint16_t dsize, uint32_t* remaining_len)
{
    int offset = 1;
    uint32_t len = 0;
    int shift = 0;
    while (offset < 5 && offset < dsize) {
        uint8_t byte = data[offset++];
        len |= (byte & 0x7F) << shift;
        shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }
    if (remaining_len)
        *remaining_len = len;
    return offset;
}

static void parse_fixed_header(Packet* p, mqtt_session_data_t* ssn)
{
    if (p->dsize < 2)
        return;
    
    uint8_t first_byte = p->data[0];
    ssn->hdr_flags = first_byte;
    ssn->msg_type = first_byte >> 4;
    ssn->dup_flag = (first_byte >> 3) & 0x01;
    ssn->qos = (first_byte >> 1) & 0x03;
    ssn->retain = first_byte & 0x01;
    skip_remaining_length(p->data, p->dsize, &ssn->remaining_len);
}

static bool parse_connect_packet(Packet* p, mqtt_session_data_t* ssn)
{
    if (p->dsize < 12)
        return false;
    
    int offset = skip_remaining_length(p->data, p->dsize, nullptr);
    
    if (offset + 2 > p->dsize)
        return false;
    ssn->proto_len = (p->data[offset] << 8) | p->data[offset + 1];
    offset += 2;
    
    if (offset + ssn->proto_len > p->dsize)
        return false;
    ssn->proto_name = p->data + offset;
    offset += ssn->proto_len;
    
    if (offset + 4 > p->dsize)
        return false;
    ssn->protocol_version = p->data[offset];
    ssn->connect_flags = p->data[offset + 1];
    ssn->conflag_reserved = ssn->connect_flags & 0x01;
    ssn->conflag_clean_session = (ssn->connect_flags >> 1) & 0x01;
    ssn->conflag_will_flag = (ssn->connect_flags >> 2) & 0x01;
    ssn->conflag_will_qos = (ssn->connect_flags >> 3) & 0x03;
    ssn->conflag_will_retain = (ssn->connect_flags >> 5) & 0x01;
    ssn->conflag_passwd = (ssn->connect_flags >> 6) & 0x01;
    ssn->conflag_uname = (ssn->connect_flags >> 7) & 0x01;
    ssn->keep_alive = (p->data[offset + 2] << 8) | p->data[offset + 3];
    offset += 4;
    
    if (offset + 2 > p->dsize)
        return false;
    ssn->client_id_len = (p->data[offset] << 8) | p->data[offset + 1];
    offset += 2;
    if (ssn->client_id_len > 0 && offset + ssn->client_id_len <= p->dsize) {
        ssn->client_id = p->data + offset;
        offset += ssn->client_id_len;
    }
    
    if (ssn->conflag_will_flag) {
        if (offset + 2 > p->dsize)
            return true;
        ssn->will_topic_len = (p->data[offset] << 8) | p->data[offset + 1];
        offset += 2;
        if (ssn->will_topic_len > 0 && offset + ssn->will_topic_len <= p->dsize) {
            ssn->will_topic = p->data + offset;
            offset += ssn->will_topic_len;
        }
        
        if (offset + 2 > p->dsize)
            return true;
        ssn->will_msg_len = (p->data[offset] << 8) | p->data[offset + 1];
        offset += 2;
        if (ssn->will_msg_len > 0 && offset + ssn->will_msg_len <= p->dsize) {
            ssn->will_msg = p->data + offset;
            offset += ssn->will_msg_len;
        }
    }
    
    if (ssn->conflag_uname) {
        if (offset + 2 > p->dsize)
            return true;
        ssn->username_len = (p->data[offset] << 8) | p->data[offset + 1];
        offset += 2;
        if (ssn->username_len > 0 && offset + ssn->username_len <= p->dsize) {
            ssn->username = p->data + offset;
            offset += ssn->username_len;
        }
    }
    
    if (ssn->conflag_passwd) {
        if (offset + 2 > p->dsize)
            return true;
        ssn->passwd_len = (p->data[offset] << 8) | p->data[offset + 1];
        offset += 2;
        if (ssn->passwd_len > 0 && offset + ssn->passwd_len <= p->dsize) {
            ssn->password = p->data + offset;
        }
    }
    
    return true;
}

static bool parse_connack_packet(Packet* p, mqtt_session_data_t* ssn)
{
    if (p->dsize < 4)
        return false;
    
    int offset = skip_remaining_length(p->data, p->dsize, nullptr);
    if (offset + 2 > p->dsize)
        return false;
    
    ssn->conack_flags = p->data[offset];
    ssn->conack_session_present = ssn->conack_flags & 0x01;
    ssn->conack_reserved = (ssn->conack_flags >> 1) & 0x7F;
    ssn->conack_return_code = p->data[offset + 1];
    
    return true;
}

static bool parse_publish_packet(Packet* p, mqtt_session_data_t* ssn)
{
    int offset = skip_remaining_length(p->data, p->dsize, nullptr);
    
    if (offset + 2 > p->dsize)
        return false;
    ssn->topic_len = (p->data[offset] << 8) | p->data[offset + 1];
    offset += 2;
    
    if (offset + ssn->topic_len > p->dsize)
        return false;
    ssn->topic = p->data + offset;
    offset += ssn->topic_len;
    
    if (ssn->qos > 0) {
        if (offset + 2 > p->dsize)
            return false;
        ssn->msg_id = (p->data[offset] << 8) | p->data[offset + 1];
        offset += 2;
    }
    
    if (offset < p->dsize) {
        ssn->payload = p->data + offset;
        ssn->payload_len = p->dsize - offset;
    }
    
    return true;
}

static bool parse_subscribe_packet(Packet* p, mqtt_session_data_t* ssn)
{
    int offset = skip_remaining_length(p->data, p->dsize, nullptr);
    
    if (offset + 2 > p->dsize)
        return false;
    ssn->msg_id = (p->data[offset] << 8) | p->data[offset + 1];
    offset += 2;
    
    ssn->sub_qos_count = 0;
    while (offset + 2 < p->dsize && ssn->sub_qos_count < 8) {
        uint16_t topic_len = (p->data[offset] << 8) | p->data[offset + 1];
        offset += 2 + topic_len;
        if (offset < p->dsize) {
            ssn->sub_qos[ssn->sub_qos_count++] = p->data[offset] & 0x03;
            offset++;
        }
    }
    
    return true;
}

static bool parse_suback_packet(Packet* p, mqtt_session_data_t* ssn)
{
    int offset = skip_remaining_length(p->data, p->dsize, nullptr);
    
    if (offset + 2 > p->dsize)
        return false;
    ssn->msg_id = (p->data[offset] << 8) | p->data[offset + 1];
    offset += 2;
    
    ssn->suback_qos_count = 0;
    while (offset < p->dsize && ssn->suback_qos_count < 8) {
        ssn->suback_qos[ssn->suback_qos_count++] = p->data[offset];
        offset++;
    }
    
    return true;
}

static bool parse_unsubscribe_packet(Packet* p, mqtt_session_data_t* ssn)
{
    int offset = skip_remaining_length(p->data, p->dsize, nullptr);
    
    if (offset + 2 > p->dsize)
        return false;
    ssn->msg_id = (p->data[offset] << 8) | p->data[offset + 1];
    
    return true;
}

static bool parse_ack_packet(Packet* p, mqtt_session_data_t* ssn)
{
    int offset = skip_remaining_length(p->data, p->dsize, nullptr);
    
    if (offset + 2 > p->dsize)
        return false;
    ssn->msg_id = (p->data[offset] << 8) | p->data[offset + 1];
    
    return true;
}

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------

unsigned MqttFlowData::inspector_id = 0;

void MqttFlowData::init()
{
    inspector_id = FlowData::create_flow_data_id();
}

MqttFlowData::MqttFlowData() : FlowData(inspector_id) // naming inspired by modbus
{
    reset();
    memset(&timing, 0, sizeof(timing));
    mqtt_stats.concurrent_sessions++;
    if(mqtt_stats.max_concurrent_sessions < mqtt_stats.concurrent_sessions)
        mqtt_stats.max_concurrent_sessions = mqtt_stats.concurrent_sessions;
}

MqttFlowData::~MqttFlowData()
{
    assert(mqtt_stats.concurrent_sessions > 0);
    mqtt_stats.concurrent_sessions--;
}

void MqttFlowData::update_timing(const struct timeval& pkt_time)
{
    if (timing.pkt_count == 0) {
        timing.first_pkt_time = pkt_time;
    }
    timing.prev_pkt_time = pkt_time;
    timing.pkt_count++;
}

int64_t MqttFlowData::get_time_delta_us() const
{
    if (timing.pkt_count < 2)
        return 0;
    return (timing.prev_pkt_time.tv_sec - timing.first_pkt_time.tv_sec) * 1000000LL +
           (timing.prev_pkt_time.tv_usec - timing.first_pkt_time.tv_usec);
}

int64_t MqttFlowData::get_time_relative_us() const
{
    if (timing.pkt_count == 0)
        return 0;
    return (timing.prev_pkt_time.tv_sec - timing.first_pkt_time.tv_sec) * 1000000LL +
           (timing.prev_pkt_time.tv_usec - timing.first_pkt_time.tv_usec);
}

void MqttFlowData::record_auth_failure(const struct timeval& pkt_time)
{
    timing.failed_auth_count++;
    
    if (timing.failed_auth_window_count == 0) {
        timing.failed_auth_window_start = pkt_time;
        timing.failed_auth_window_count = 1;
    } else {
        int64_t window_elapsed = (pkt_time.tv_sec - timing.failed_auth_window_start.tv_sec) * 1000000LL +
                                 (pkt_time.tv_usec - timing.failed_auth_window_start.tv_usec);
        if (window_elapsed > 1000000) {
            timing.failed_auth_window_start = pkt_time;
            timing.failed_auth_window_count = 1;
        } else {
            timing.failed_auth_window_count++;
        }
    }
}

float MqttFlowData::get_failed_auth_per_second(const struct timeval& pkt_time) const
{
    if (timing.failed_auth_window_count == 0)
        return 0.0f;
    
    int64_t window_elapsed = (pkt_time.tv_sec - timing.failed_auth_window_start.tv_sec) * 1000000LL +
                             (pkt_time.tv_usec - timing.failed_auth_window_start.tv_usec);
    
    if (window_elapsed <= 0)
        return static_cast<float>(timing.failed_auth_window_count);
    
    return static_cast<float>(timing.failed_auth_window_count) * 1000000.0f / static_cast<float>(window_elapsed);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Mqtt : public Inspector
{
public:
    void eval(Packet*) override;
    
    bool get_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b) override
    { return (ibt == InspectionBuffer::IBT_BODY) ? get_buf_mqtt_payload(p, b) : false; }
    
    bool get_buf(unsigned id, snort::Packet* p, snort::InspectionBuffer& b) override
    {
        switch(id) {
            case MQTT_TOPIC_BUFID: return get_buf_mqtt_topic(p, b);
            case MQTT_PAYLOAD_BUFID: return get_buf_mqtt_payload(p, b);
            case MQTT_CLIENT_ID_BUFID: return get_buf_mqtt_client_id(p, b);
        }
        return false;
    }

    StreamSplitter* get_splitter(bool c2s) override
    { return new MqttSplitter(c2s); }
};

void Mqtt::eval(Packet* p)
{
    Profile profile(mqtt_prof);   // cppcheck-suppress unreadVariable

    // Preconditions - what we registered for
    assert(p->has_tcp_data()); // Only called when payload exists

    MqttFlowData* mfd =
        (MqttFlowData*)p->flow->get_flow_data(MqttFlowData::inspector_id);

    if ( !p->is_full_pdu() )
    {
        if ( mfd )
            mfd->reset();

        // If a packet is rebuilt, but not a full PDU, then it's garbage that
        // got flushed at the end of a stream.
        if ( p->packet_flags & (PKT_REBUILT_STREAM|PKT_PDU_HEAD) )
            DetectionEngine::queue_event(GID_MQTT, MQTT_BAD_LENGTH);

        return;
    }

    if ( !mfd )
    {
        mfd = new MqttFlowData;
        p->flow->set_flow_data(mfd);
        mqtt_stats.sessions++;
    }

    // Allow multiple detections per packet
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;

    mqtt_stats.frames++;

    if (p->dsize < 2)
        return;

    mfd->reset();
    
    struct timeval pkt_time;
    if (p->pkth)
        pkt_time = { static_cast<time_t>(p->pkth->ts.tv_sec), 
                     static_cast<suseconds_t>(p->pkth->ts.tv_usec) };
    else
        gettimeofday(&pkt_time, nullptr);
    mfd->update_timing(pkt_time);

    parse_fixed_header(p, &mfd->ssn_data); // Runs for ALL packets
    
    uint8_t msg_type = mfd->ssn_data.msg_type;

    switch (msg_type) // Cases based on Table 2.1, 2.2.1 MQTT Control Packet type
    {
    case 1:  // CONNECT
        parse_connect_packet(p, &mfd->ssn_data); // Extracts MORE fields
        break;
        
    case 2:  // CONNACK
        parse_connack_packet(p, &mfd->ssn_data); // Extracts MORE fields
        if (mfd->ssn_data.conack_return_code != 0) {
            mfd->record_auth_failure(pkt_time);
        }
        break;
        
    case 3:  // PUBLISH
        parse_publish_packet(p, &mfd->ssn_data); // Extracts MORE fields
        break;
        
    case 4:  // PUBACK – NO extra fields
    case 5:  // PUBREC – NO extra fields
    case 6:  // PUBREL – NO extra fields
    case 7:  // PUBCOMP – NO extra fields
    case 11: // UNSUBACK – NO extra fields
        parse_ack_packet(p, &mfd->ssn_data); // Extracts MORE fields
        break;
        
    case 8:  // SUBSCRIBE
        parse_subscribe_packet(p, &mfd->ssn_data); // Extracts MORE fields
        break;
        
    case 9:  // SUBACK
        parse_suback_packet(p, &mfd->ssn_data); // Extracts MORE fields
        break;
        
    case 10: // UNSUBSCRIBE
        parse_unsubscribe_packet(p, &mfd->ssn_data); // Extracts MORE fields
        break;
        
    case 12: // PINGREQ – NO extra fields, 2 bytes total (fixed header only)
    case 13: // PINGRESP – NO extra fields, 2 bytes total (fixed header only)
    case 14: // DISCONNECT – NO extra fields, 2 bytes total (fixed header only)
        break;
        
    default:
        DetectionEngine::queue_event(GID_MQTT, MQTT_RESERVED_TYPE);
        break;
    }
    
    // Publish comprehensive feature event for ML (every packet)
    {
        MqttFeatureEvent fe;
        
        // Fixed header
        fe.msg_type = mfd->ssn_data.msg_type;
        fe.dup_flag = mfd->ssn_data.dup_flag;
        fe.qos = mfd->ssn_data.qos;
        fe.retain = mfd->ssn_data.retain;
        fe.remaining_len = mfd->ssn_data.remaining_len;
        
        // CONNECT fields
        fe.protocol_version = mfd->ssn_data.protocol_version;
        fe.connect_flags = mfd->ssn_data.connect_flags;
        fe.conflag_clean_session = mfd->ssn_data.conflag_clean_session;
        fe.conflag_will_flag = mfd->ssn_data.conflag_will_flag;
        fe.conflag_will_qos = mfd->ssn_data.conflag_will_qos;
        fe.conflag_will_retain = mfd->ssn_data.conflag_will_retain;
        fe.conflag_passwd = mfd->ssn_data.conflag_passwd;
        fe.conflag_uname = mfd->ssn_data.conflag_uname;
        fe.keep_alive = mfd->ssn_data.keep_alive;
        fe.client_id_len = mfd->ssn_data.client_id_len;
        fe.username_len = mfd->ssn_data.username_len;
        fe.passwd_len = mfd->ssn_data.passwd_len;
        fe.will_topic_len = mfd->ssn_data.will_topic_len;
        fe.will_msg_len = mfd->ssn_data.will_msg_len;
        
        // CONNACK fields
        fe.conack_return_code = mfd->ssn_data.conack_return_code;
        fe.conack_session_present = mfd->ssn_data.conack_session_present;
        
        // PUBLISH fields
        fe.topic_len = mfd->ssn_data.topic_len;
        fe.payload_len = mfd->ssn_data.payload_len;
        fe.msg_id = mfd->ssn_data.msg_id;
        
        // Timing features
        fe.time_delta_us = mfd->get_time_delta_us();
        fe.time_relative_us = mfd->get_time_relative_us();
        
        // Brute force detection
        fe.failed_auth_per_second = mfd->get_failed_auth_per_second(pkt_time);
        fe.failed_auth_count = mfd->timing.failed_auth_count;
        
        // Flow statistics
        fe.pkt_count = mfd->timing.pkt_count;
        
        DataBus::publish(DataBus::get_id(mqtt_pub_key), MqttEventIds::MQTT_FEATURE, fe, p->flow);
    }
}

//-------------------------------------------------------------------------
// plugin stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new MqttModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void mqtt_init()
{
    MqttFlowData::init();
}

static Inspector* mqtt_ctor(Module*)
{
    return new Mqtt;
}

static void mqtt_dtor(Inspector* p)
{
    delete p;
}

//-------------------------------------------------------------------------

static const char* mqtt_bufs[] =
{
    "mqtt_topic",
    "mqtt_payload",
    "mqtt_client_id",
    nullptr
};

static const InspectApi mqtt_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MQTT_NAME,
        MQTT_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    mqtt_bufs,
    "mqtt",
    mqtt_init,
    nullptr,
    nullptr, // tinit
    nullptr, // tterm
    mqtt_ctor,
    mqtt_dtor,
    nullptr, // ssn
    nullptr  // reset
};

// External IPS option APIs
extern const BaseApi* ips_mqtt_topic;
extern const BaseApi* ips_mqtt_payload;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_mqtt[] =
#endif
{
    &mqtt_api.base,
    ips_mqtt_topic,
    ips_mqtt_payload,
    nullptr
};
