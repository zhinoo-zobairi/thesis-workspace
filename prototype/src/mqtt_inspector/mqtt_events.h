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
        MQTT_FEATURE,   // Comprehensive feature event for ML (published for every packet)
        MAX
    };
};

// PubKey for registering MQTT as a publisher
const snort::PubKey mqtt_pub_key { "mqtt", MqttEventIds::MAX };

// MqttFeatureEvent is a COMPREHENSIVE event that contains ALL features extracted from ANY MQTT packet type
class MqttFeatureEvent : public snort::DataEvent // All fields default to 0
{
public:
    // Fixed header fields
    uint8_t msg_type = 0;           // MQTT packet type (1-14)
    uint8_t dup_flag = 0;           // Duplicate delivery flag
    uint8_t qos = 0;                // Quality of Service (0-2)
    uint8_t retain = 0;             // Retain flag
    uint32_t remaining_len = 0;     // Remaining length from fixed header
    
    // CONNECT fields
    uint8_t protocol_version = 0;   // MQTT version (3, 4, or 5)
    uint8_t connect_flags = 0;      // Raw connect flags byte
    uint8_t conflag_clean_session = 0;
    uint8_t conflag_will_flag = 0;
    uint8_t conflag_will_qos = 0;
    uint8_t conflag_will_retain = 0;
    uint8_t conflag_passwd = 0;
    uint8_t conflag_uname = 0;
    uint16_t keep_alive = 0;
    uint16_t client_id_len = 0;
    uint16_t username_len = 0;
    uint16_t passwd_len = 0;
    uint16_t will_topic_len = 0;
    uint16_t will_msg_len = 0;
    
    // CONNACK fields
    uint8_t conack_return_code = 0;
    uint8_t conack_session_present = 0;
    
    // PUBLISH fields
    uint16_t topic_len = 0;
    uint16_t payload_len = 0;
    uint16_t msg_id = 0;            // Packet identifier (for QoS > 0)
    
    // Timing features (microseconds)
    int64_t time_delta_us = 0;      // Time since first packet in flow
    int64_t time_relative_us = 0;   // Same as delta (for compatibility)
    
    // Brute force detection
    float failed_auth_per_second = 0.0f;
    uint32_t failed_auth_count = 0;
    
    // Flow statistics
    uint32_t pkt_count = 0;         // Packet count in this flow
};

} // namespace snort

#endif
