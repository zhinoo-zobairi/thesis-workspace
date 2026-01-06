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

// mqtt_paf.h author Zhinoo Zobairi
// Protocol-Aware Flushing (PAF) code for the MQTT inspector.

#ifndef MQTT_PAF_H
#define MQTT_PAF_H

#include "stream/stream_splitter.h"

// State machine for MQTT packet parsing
enum mqtt_paf_state_t
{
    MQTT_PAF_STATE__FIXED_HEADER,      // Reading first byte (packet type + flags)
    MQTT_PAF_STATE__REMAINING_LEN,     // Reading remaining length (1-4 bytes)
    MQTT_PAF_STATE__PAYLOAD,           // Reading packet payload
    MQTT_PAF_STATE__SET_FLUSH          // Ready to flush
};

class MqttSplitter : public snort::StreamSplitter
{
public:
    MqttSplitter(bool c2s);

    Status scan(snort::Packet*, const uint8_t* data, uint32_t len, uint32_t flags,
        uint32_t* fp) override;

    bool is_paf() override { return true; }

private:
    mqtt_paf_state_t state;
    uint32_t mqtt_length;       // Remaining length from MQTT header
    uint32_t length_bytes_read; // How many bytes of remaining length we've read
    uint32_t payload_read;      // How many payload bytes we've read
};

#endif
