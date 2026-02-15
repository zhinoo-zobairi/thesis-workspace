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

// mqtt_ml_module.cc author Zhinoo Zobairi
// Module implementation for MQTT ML inspector

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt_ml_module.h"

using namespace snort;

THREAD_LOCAL MqttMLStats mqtt_ml_stats;
THREAD_LOCAL ProfileStats mqtt_ml_prof;

//-------------------------------------------------------------------------
// mqtt_ml module parameters
//-------------------------------------------------------------------------

static const Parameter mqtt_ml_params[] =
{
    { "anomaly_threshold", Parameter::PT_REAL, "0.0:1.0", "0.5",
      "threshold for anomaly detection (0.0 = always alert, 1.0 = never alert)" },

    { "enabled", Parameter::PT_BOOL, nullptr, "true",
      "enable or disable ML-based anomaly detection" },

    { "model_path", Parameter::PT_STRING, nullptr, nullptr,
      "path to TF Lite model file (.tflite)" },

    { "threshold_path", Parameter::PT_STRING, nullptr, nullptr,
      "path to threshold file (overrides anomaly_threshold)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// mqtt_ml rules
//-------------------------------------------------------------------------

static const RuleMap mqtt_ml_rules[] =
{
    { MQTT_ML_SID, "MQTT anomaly detected by ML classifier" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// mqtt_ml pegs
//-------------------------------------------------------------------------

static const PegInfo mqtt_ml_pegs[] =
{
    { CountType::SUM, "events_received", "total MQTT feature events received" },
    { CountType::SUM, "anomalies_detected", "MQTT anomalies detected by ML" },
    { CountType::SUM, "connect_packets", "CONNECT packets analyzed" },
    { CountType::SUM, "publish_packets", "PUBLISH packets analyzed" },
    { CountType::SUM, "other_packets", "other MQTT packets analyzed" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// mqtt_ml module methods
//-------------------------------------------------------------------------

MqttMLModule::MqttMLModule() :
    Module(MQTT_ML_NAME, MQTT_ML_HELP, mqtt_ml_params)
{
    conf.anomaly_threshold = 0.5;
    conf.enabled = true;
}

bool MqttMLModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("anomaly_threshold"))
        conf.anomaly_threshold = v.get_real();
    else if (v.is("enabled"))
        conf.enabled = v.get_bool();
    else if (v.is("model_path"))
        conf.model_path = v.get_string();
    else if (v.is("threshold_path"))
        conf.threshold_path = v.get_string();
    else
        return false;

    return true;
}

bool MqttMLModule::end(const char*, int, SnortConfig*)
{
    return true;
}

const RuleMap* MqttMLModule::get_rules() const
{
    return mqtt_ml_rules;
}

const PegInfo* MqttMLModule::get_pegs() const
{
    return mqtt_ml_pegs;
}

PegCount* MqttMLModule::get_counts() const
{
    return reinterpret_cast<PegCount*>(&mqtt_ml_stats);
}

ProfileStats* MqttMLModule::get_profile() const
{
    return &mqtt_ml_prof;
}
