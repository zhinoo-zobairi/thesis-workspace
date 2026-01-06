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

// mqtt_module.cc author Zhinoo Zobairi

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt_module.h"

#include "profiler/profiler.h"

#include "mqtt.h"

using namespace snort;

THREAD_LOCAL ProfileStats mqtt_prof;

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

const PegInfo peg_names[] =
{
    { CountType::SUM, "sessions", "total sessions processed" },
    { CountType::SUM, "frames", "total MQTT messages" },
    { CountType::NOW, "concurrent_sessions", "total concurrent mqtt sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent mqtt sessions" },

    { CountType::END, nullptr, nullptr }
};

const PegInfo* MqttModule::get_pegs() const
{ return peg_names; }

PegCount* MqttModule::get_counts() const
{ return (PegCount*)&mqtt_stats; }

//-------------------------------------------------------------------------
// rules
//-------------------------------------------------------------------------

#define MQTT_BAD_LENGTH_STR \
    "MQTT packet length does not match expected size"

#define MQTT_BAD_PROTO_ID_STR    "MQTT protocol name is invalid"
#define MQTT_RESERVED_TYPE_STR   "reserved MQTT packet type in use"

static const RuleMap mqtt_rules[] =
{
    { MQTT_BAD_LENGTH, MQTT_BAD_LENGTH_STR },
    { MQTT_BAD_PROTO_ID, MQTT_BAD_PROTO_ID_STR },
    { MQTT_RESERVED_TYPE, MQTT_RESERVED_TYPE_STR },

    { 0, nullptr }
};

const RuleMap* MqttModule::get_rules() const
{ return mqtt_rules; }

//-------------------------------------------------------------------------
// params
//-------------------------------------------------------------------------

MqttModule::MqttModule() :
    Module(MQTT_NAME, MQTT_HELP)
{ }
