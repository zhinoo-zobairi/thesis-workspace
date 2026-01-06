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

// mqtt_paf.cc author Your Name
// Protocol-Aware Flushing implementation for MQTT.
// Handles MQTT's variable-length encoding for packet boundaries.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt_paf.h"

using namespace snort;

MqttSplitter::MqttSplitter(bool c2s) : StreamSplitter(c2s)
{
    state = MQTT_PAF_STATE__FIXED_HEADER;
    mqtt_length = 0;
    length_bytes_read = 0;
    payload_read = 0;
}

StreamSplitter::Status MqttSplitter::scan(
    Packet*, const uint8_t* data, uint32_t len, uint32_t, uint32_t* fp)
{
    uint32_t idx = 0;

    while (idx < len)
    {
        switch (state)
        {
        case MQTT_PAF_STATE__FIXED_HEADER:
            // First byte contains packet type (bits 7-4) and flags (bits 3-0)
            // We just skip it for PAF purposes
            idx++;
            state = MQTT_PAF_STATE__REMAINING_LEN;
            mqtt_length = 0;
            length_bytes_read = 0;
            break;

        case MQTT_PAF_STATE__REMAINING_LEN:
        {
            // MQTT uses variable-length encoding (1-4 bytes)
            // Each byte: bit 7 = continuation flag, bits 6-0 = value
            uint8_t byte = data[idx++];
            mqtt_length |= (byte & 0x7F) << (7 * length_bytes_read);
            length_bytes_read++;

            if ((byte & 0x80) == 0)
            {
                // No continuation bit - done with remaining length
                if (mqtt_length == 0)
                {
                    // No payload, flush immediately
                    state = MQTT_PAF_STATE__SET_FLUSH;
                }
                else
                {
                    state = MQTT_PAF_STATE__PAYLOAD;
                    payload_read = 0;
                }
            }
            else if (length_bytes_read >= 4)
            {
                // Protocol violation: remaining length uses at most 4 bytes
                // Flush what we have and reset
                *fp = idx;
                state = MQTT_PAF_STATE__FIXED_HEADER;
                return FLUSH;
            }
            break;
        }

        case MQTT_PAF_STATE__PAYLOAD:
        {
            // Calculate how much payload data is available
            uint32_t remaining = len - idx;
            uint32_t need = mqtt_length - payload_read;

            if (remaining >= need)
            {
                // We have the complete packet
                idx += need;
                state = MQTT_PAF_STATE__SET_FLUSH;
            }
            else
            {
                // Partial payload, need more data
                payload_read += remaining;
                return SEARCH;
            }
            break;
        }

        case MQTT_PAF_STATE__SET_FLUSH:
            *fp = idx;
            state = MQTT_PAF_STATE__FIXED_HEADER;
            return FLUSH;
        }
    }

    // If we ended in SET_FLUSH state, flush now
    if (state == MQTT_PAF_STATE__SET_FLUSH)
    {
        *fp = idx;
        state = MQTT_PAF_STATE__FIXED_HEADER;
        return FLUSH;
    }

    return SEARCH;
}
