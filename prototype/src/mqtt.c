#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt.h"

#include "detection/detection_engine.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "mqtt_module.h"
#include "mqtt_paf.h"

using namespace snort;

THREAD_LOCAL MqttStats mqtt_stats;


enum MqttBufId
{
    MQTT_TOPIC_BUFID = 1,
    MQTT_PAYLOAD_BUFID,
    MQTT_CLIENT_ID_BUFID
};

static int parse_mqtt_publish_header(Packet* p, uint8_t* packet_type, uint8_t* qos)
{
    if (!p->is_full_pdu() || p->dsize < 2)
        return -1;
    
    uint8_t first_byte = p->data[0];
    *packet_type = first_byte >> 4;
    *qos = (first_byte >> 1) & 0x03;
    
    if (*packet_type != 3)
        return -1;
    
    int offset = 1;
    while (offset < 5 && offset < p->dsize) {
        if ((p->data[offset++] & 0x80) == 0)
            break;  // Last length byte
    }
    
    return offset; 
}

bool get_buf_mqtt_topic(Packet* p, InspectionBuffer& b)
{
    uint8_t packet_type, qos;
    int offset = parse_mqtt_publish_header(p, &packet_type, &qos);
    if (offset < 0)
        return false;
    
    if (offset + 2 > p->dsize)
        return false;
    
    uint16_t topic_len = (p->data[offset] << 8) | p->data[offset + 1];
    offset += 2;
    
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
    
    if (offset + 2 > p->dsize)
        return false;
    
    uint16_t topic_len = (p->data[offset] << 8) | p->data[offset + 1];
    offset += 2 + topic_len;
    
    if (qos > 0)
        offset += 2;
    
    if (offset >= p->dsize)
        return false;
    
    b.data = p->data + offset;
    b.len = p->dsize - offset;
    return true;
}

bool get_buf_mqtt_client_id(Packet* p, InspectionBuffer& b)
{
    // TODO: Parse MQTT CONNECT packet and extract client ID
    // 1. Check packet_type == 1 (CONNECT)
    // 2. Skip fixed header + protocol name/version/flags
    // 3. Read 2-byte client ID length
    // 4. Set b.data to client ID bytes
    return false;  // Placeholder
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

    // TODO: Implement MQTT packet parsing
    // Parse fixed header, extract packet type, QoS, etc.
    // Store in mfd->ssn_data
    // For now, just increment frame counter:
    mqtt_stats.frames++;
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

// TODO: Adding IPS option plugins 

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_mqtt[] =
#endif
{
    &mqtt_api.base,
    nullptr
};
