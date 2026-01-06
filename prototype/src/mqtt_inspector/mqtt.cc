#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt.h"

#include "detection/detection_engine.h"
#include "framework/data_bus.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "mqtt_events.h"
#include "mqtt_module.h"
#include "mqtt_paf.h"

using namespace snort;

THREAD_LOCAL MqttStats mqtt_stats;

// Publisher ID for MQTT events (initialized in mqtt_init)
static THREAD_LOCAL unsigned mqtt_pub_id = 0;

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
    
    // 2. Check packet type (must be CONNECT = 1)
    uint8_t packet_type = p->data[0] >> 4;
    if (packet_type != 1)
        return false;
    
    // 3. Skip remaining length bytes (1-4 bytes with bit 7 = continuation flag)
    int offset = 1;
    while (offset < 5 && offset < p->dsize) {
        if ((p->data[offset++] & 0x80) == 0)
            break;
    }
    
    // 4. Skip Protocol Name (2-byte length + string "MQTT")
    if (offset + 2 > p->dsize)
        return false;
    uint16_t proto_len = (p->data[offset] << 8) | p->data[offset + 1];
    offset += 2 + proto_len;
    
    // 5. Skip Version (1 byte) + Connect Flags (1 byte) + Keep Alive (2 bytes)
    offset += 4;
    
    // 6. Read Client ID Length
    if (offset + 2 > p->dsize)
        return false;
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
// flow stuff
//-------------------------------------------------------------------------

unsigned MqttFlowData::inspector_id = 0;

void MqttFlowData::init()
{
    inspector_id = FlowData::create_flow_data_id();
}

MqttFlowData::MqttFlowData() : FlowData(inspector_id)
{
    reset();
    mqtt_stats.concurrent_sessions++;
    if(mqtt_stats.max_concurrent_sessions < mqtt_stats.concurrent_sessions)
        mqtt_stats.max_concurrent_sessions = mqtt_stats.concurrent_sessions;
}

MqttFlowData::~MqttFlowData()
{
    assert(mqtt_stats.concurrent_sessions > 0);
    mqtt_stats.concurrent_sessions--;
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
    assert(p->has_tcp_data());

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

    // Parse packet type from first byte
    if (p->dsize < 2)
        return;

    uint8_t first_byte = p->data[0];
    uint8_t packet_type = first_byte >> 4;
    uint8_t qos = (first_byte >> 1) & 0x03;

    // Store in flow data
    mfd->ssn_data.packet_type = packet_type;
    mfd->ssn_data.qos = qos;

    // Publish events based on packet type
    if (packet_type == 3)  // PUBLISH
    {
        InspectionBuffer topic_buf, payload_buf;
        if (get_buf_mqtt_topic(p, topic_buf) && get_buf_mqtt_payload(p, payload_buf))
        {
            MqttPublishEvent event(topic_buf.data, topic_buf.len,
                                   payload_buf.data, payload_buf.len, qos);
            DataBus::publish(mqtt_pub_id, MqttEventIds::MQTT_PUBLISH, event, p->flow);
        }
    }
    else if (packet_type == 1)  // CONNECT
    {
        InspectionBuffer client_id_buf;
        const uint8_t* cid = nullptr;
        uint16_t cid_len = 0;
        if (get_buf_mqtt_client_id(p, client_id_buf))
        {
            cid = client_id_buf.data;
            cid_len = client_id_buf.len;
        }
        MqttConnectEvent event(cid, cid_len);
        DataBus::publish(mqtt_pub_id, MqttEventIds::MQTT_CONNECT, event, p->flow);
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
    mqtt_pub_id = DataBus::get_id(mqtt_pub_key);
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
SO_PUBLIC const BaseApi* snort_plugins[]
#else
const BaseApi* sin_mqtt[]
#endif
{
    &mqtt_api.base,
    ips_mqtt_topic,
    ips_mqtt_payload,
    nullptr
};
