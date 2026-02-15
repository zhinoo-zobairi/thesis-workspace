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

// mqtt_ml_module.h author Zhinoo Zobairi
// Module for MQTT ML-based anomaly detection inspector

#ifndef MQTT_ML_MODULE_H
#define MQTT_ML_MODULE_H

#include "framework/module.h"
#include "main/thread.h"
#include "profiler/profiler.h"

#include <string>

#define MQTT_ML_GID 412
#define MQTT_ML_SID 1

#define MQTT_ML_NAME "mqtt_ml"
#define MQTT_ML_HELP "machine learning based MQTT anomaly detector"

struct MqttMLStats
{
    PegCount events_received;
    PegCount anomalies_detected;
    PegCount connect_packets;
    PegCount publish_packets;
    PegCount other_packets;
};

extern THREAD_LOCAL MqttMLStats mqtt_ml_stats;
extern THREAD_LOCAL snort::ProfileStats mqtt_ml_prof;

struct MqttMLConfig
{
    double anomaly_threshold;  // Threshold for anomaly detection (0.0 - 1.0)
    bool enabled;              // Whether ML detection is enabled
    std::string model_path;    // Path to TF Lite model file
    std::string threshold_path; // Path to threshold file
};

class MqttMLModule : public snort::Module
{
public:
    MqttMLModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const MqttMLConfig& get_config() const
    { return conf; }

    unsigned get_gid() const override
    { return MQTT_ML_GID; }

    const snort::RuleMap* get_rules() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Usage get_usage() const override
    { return INSPECT; }

    snort::ProfileStats* get_profile() const override;

private:
    MqttMLConfig conf = {};
};

#endif
