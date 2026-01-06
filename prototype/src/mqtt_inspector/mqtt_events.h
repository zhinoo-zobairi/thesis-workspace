//--------------------------------------------------------------------------
// Copyright (C) 2025 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// mqtt_events.h author Zhinoo Zobairi
// MQTT events published via DataBus for other components to consume.

#ifndef MQTT_EVENTS_H
#define MQTT_EVENTS_H

#include "framework/data_bus.h"

namespace snort
{

// Event IDs for MQTT pub/sub
struct MqttEventIds
{
    enum : unsigned
    {
        MQTT_PUBLISH,   // A PUBLISH packet was received
        MQTT_CONNECT,   // A CONNECT packet was received
        MAX
    };
};

// PubKey for registering MQTT as a publisher
const snort::PubKey mqtt_pub_key { "mqtt", MqttEventIds::MAX };

// Event published when an MQTT PUBLISH packet is received
class MqttPublishEvent : public snort::DataEvent
{
public:
    MqttPublishEvent(const uint8_t* topic_data, uint16_t topic_len,
                     const uint8_t* payload_data, uint16_t payload_len,
                     uint8_t qos_level)
        : topic(topic_data), topic_length(topic_len),
          payload(payload_data), payload_length(payload_len),
          qos(qos_level) { }

    const uint8_t* get_topic() const { return topic; }
    uint16_t get_topic_length() const { return topic_length; }

    const uint8_t* get_payload() const { return payload; }
    uint16_t get_payload_length() const { return payload_length; }

    uint8_t get_qos() const { return qos; }

private:
    const uint8_t* topic;
    uint16_t topic_length;
    const uint8_t* payload;
    uint16_t payload_length;
    uint8_t qos;
};

// Event published when an MQTT CONNECT packet is received
class MqttConnectEvent : public snort::DataEvent
{
public:
    MqttConnectEvent(const uint8_t* client_id_data, uint16_t client_id_len)
        : client_id(client_id_data), client_id_length(client_id_len) { }

    const uint8_t* get_client_id() const { return client_id; }
    uint16_t get_client_id_length() const { return client_id_length; }

private:
    const uint8_t* client_id;
    uint16_t client_id_length;
};

} // namespace snort

#endif
