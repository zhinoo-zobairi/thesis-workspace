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

// mqtt_module.h author Zhinoo Zobairi

#ifndef MQTT_MODULE_H
#define MQTT_MODULE_H

#include "framework/module.h"

// GID for MQTT inspector (pick unused number)
#define GID_MQTT 200

// Event IDs
#define MQTT_BAD_LENGTH      1
#define MQTT_BAD_PROTO_ID    2
#define MQTT_RESERVED_TYPE   3

// Module name and help text
#define MQTT_NAME "mqtt"
#define MQTT_HELP "mqtt inspection"

// Profiling stats (declared here, defined in mqtt_module.cc)
extern THREAD_LOCAL snort::ProfileStats mqtt_prof;

class MqttModule : public snort::Module
{
public:
    MqttModule();

    unsigned get_gid() const override
    { return GID_MQTT; }

    const snort::RuleMap* get_rules() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override
    { return &mqtt_prof; }

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }
};

#endif
