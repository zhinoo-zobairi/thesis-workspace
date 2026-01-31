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

// mqtt_ml.cc author Zhinoo Zobairi
// MQTT ML-based anomaly detection inspector implementation

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt_ml.h"

#include <cassert>
#include <cmath>

#include "detection/detection_engine.h"
#include "framework/data_bus.h"
#include "log/messages.h"
#include "profiler/profiler.h"

#include "mqtt_events.h"

using namespace snort;

//--------------------------------------------------------------------------
// MQTT Feature Event Handler
// Subscribes to MqttFeatureEvent and runs ML inference
//--------------------------------------------------------------------------

class MqttFeatureHandler : public DataHandler
{
public:
    MqttFeatureHandler(const MqttML& ins)
        : DataHandler(MQTT_ML_NAME), inspector(ins) {}

    void handle(DataEvent& de, Flow*) override;

private:
    const MqttML& inspector;
    
    // Build feature vector from event (returns array of normalized features)
    void build_feature_vector(const MqttFeatureEvent& fe, float* features, size_t max_features);
    
    // ML inference stub - returns anomaly score (0.0 = normal, 1.0 = anomaly)
    float run_inference(const float* features, size_t num_features);
};

void MqttFeatureHandler::handle(DataEvent& de, Flow*)
{
    Profile profile(mqtt_ml_prof);
    
    const MqttFeatureEvent& fe = static_cast<const MqttFeatureEvent&>(de);
    
    mqtt_ml_stats.events_received++;
    
    // Track packet types for statistics
    switch (fe.msg_type)
    {
    case 1:  // CONNECT
        mqtt_ml_stats.connect_packets++;
        break;
    case 3:  // PUBLISH
        mqtt_ml_stats.publish_packets++;
        break;
    default:
        mqtt_ml_stats.other_packets++;
        break;
    }
    
    const MqttMLConfig& conf = inspector.get_config();
    
    if (!conf.enabled)
        return;
    
    // Build feature vector from the event
    constexpr size_t NUM_FEATURES = 30;
    float features[NUM_FEATURES] = {0};
    build_feature_vector(fe, features, NUM_FEATURES);
    
    // Run ML inference
    float anomaly_score = run_inference(features, NUM_FEATURES);
    
    // Check against threshold and alert if anomaly detected
    if (anomaly_score > conf.anomaly_threshold)
    {
        mqtt_ml_stats.anomalies_detected++;
        DetectionEngine::queue_event(MQTT_ML_GID, MQTT_ML_SID);
    }
}

void MqttFeatureHandler::build_feature_vector(const MqttFeatureEvent& fe, 
                                               float* features, 
                                               size_t max_features)
{
    if (max_features < 30)
        return;
    
    size_t i = 0;
    
    // Fixed header features (indices 0-4)
    features[i++] = static_cast<float>(fe.msg_type) / 14.0f;        // Normalized to 0-1
    features[i++] = static_cast<float>(fe.dup_flag);                 // Already 0 or 1
    features[i++] = static_cast<float>(fe.qos) / 2.0f;              // Normalized to 0-1
    features[i++] = static_cast<float>(fe.retain);                   // Already 0 or 1
    features[i++] = std::min(static_cast<float>(fe.remaining_len) / 65535.0f, 1.0f);
    
    // CONNECT features (indices 5-14)
    features[i++] = static_cast<float>(fe.protocol_version) / 5.0f; // MQTT versions 3-5
    features[i++] = static_cast<float>(fe.conflag_clean_session);
    features[i++] = static_cast<float>(fe.conflag_will_flag);
    features[i++] = static_cast<float>(fe.conflag_will_qos) / 2.0f;
    features[i++] = static_cast<float>(fe.conflag_will_retain);
    features[i++] = static_cast<float>(fe.conflag_passwd);
    features[i++] = static_cast<float>(fe.conflag_uname);
    features[i++] = std::min(static_cast<float>(fe.keep_alive) / 3600.0f, 1.0f);
    features[i++] = std::min(static_cast<float>(fe.client_id_len) / 256.0f, 1.0f);
    features[i++] = std::min(static_cast<float>(fe.username_len) / 256.0f, 1.0f);
    
    // More CONNECT features (indices 15-17)
    features[i++] = std::min(static_cast<float>(fe.passwd_len) / 256.0f, 1.0f);
    features[i++] = std::min(static_cast<float>(fe.will_topic_len) / 256.0f, 1.0f);
    features[i++] = std::min(static_cast<float>(fe.will_msg_len) / 1024.0f, 1.0f);
    
    // CONNACK features (indices 18-19)
    features[i++] = static_cast<float>(fe.conack_return_code) / 5.0f;
    features[i++] = static_cast<float>(fe.conack_session_present);
    
    // PUBLISH features (indices 20-22)
    features[i++] = std::min(static_cast<float>(fe.topic_len) / 256.0f, 1.0f);
    features[i++] = std::min(static_cast<float>(fe.payload_len) / 65535.0f, 1.0f);
    features[i++] = std::min(static_cast<float>(fe.msg_id) / 65535.0f, 1.0f);
    
    // Timing features (indices 23-24)
    // Normalize time to seconds, cap at 1 hour
    features[i++] = std::min(static_cast<float>(fe.time_delta_us) / 3600000000.0f, 1.0f);
    features[i++] = std::min(static_cast<float>(fe.time_relative_us) / 3600000000.0f, 1.0f);
    
    // Brute force features (indices 25-26)
    features[i++] = std::min(fe.failed_auth_per_second / 100.0f, 1.0f);
    features[i++] = std::min(static_cast<float>(fe.failed_auth_count) / 100.0f, 1.0f);
    
    // Flow statistics (index 27)
    features[i++] = std::min(static_cast<float>(fe.pkt_count) / 10000.0f, 1.0f);
    
    // Reserved for future features (indices 28-29)
    features[i++] = 0.0f;
    features[i++] = 0.0f;
}

float MqttFeatureHandler::run_inference(const float* features, size_t num_features)
{
    // STUB: Placeholder ML inference
    // This will be replaced with actual ML model inference
    // For now, implement simple heuristic-based detection
    
    (void)num_features;  // Unused for now
    
    float anomaly_score = 0.0f;
    
    // Heuristic 1: High failed auth rate indicates brute force attack
    // features[25] = failed_auth_per_second (normalized)
    if (features[25] > 0.1f)  // More than 10 failures/second
        anomaly_score = std::max(anomaly_score, features[25]);
    
    // Heuristic 2: Unusual protocol version
    // features[5] = protocol_version (normalized, expecting 0.6-1.0 for versions 3-5)
    if (features[5] > 0.0f && features[5] < 0.5f)  // Version < 3
        anomaly_score = std::max(anomaly_score, 0.8f);
    
    // Heuristic 3: Very large payloads might indicate DoS
    // features[21] = payload_len (normalized)
    if (features[21] > 0.9f)  // Very large payload
        anomaly_score = std::max(anomaly_score, 0.3f);
    
    // Heuristic 4: Many failed auth attempts
    // features[26] = failed_auth_count (normalized)
    if (features[26] > 0.5f)  // More than 50 failures
        anomaly_score = std::max(anomaly_score, 0.7f);
    
    return anomaly_score;
}

//--------------------------------------------------------------------------
// MqttML inspector methods
//--------------------------------------------------------------------------

void MqttML::show(const SnortConfig*) const
{
    ConfigLogger::log_value("anomaly_threshold", conf.anomaly_threshold);
    ConfigLogger::log_flag("enabled", conf.enabled);
}

bool MqttML::configure(SnortConfig*)
{
    // Subscribe to MQTT feature events
    DataBus::subscribe(mqtt_pub_key, MqttEventIds::MQTT_FEATURE,
        new MqttFeatureHandler(*this));
    
    return true;
}

//--------------------------------------------------------------------------
// API stuff
//--------------------------------------------------------------------------

static Module* mod_ctor()
{ return new MqttMLModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* mqtt_ml_ctor(Module* m)
{
    const MqttMLModule* mod = reinterpret_cast<const MqttMLModule*>(m);
    return new MqttML(mod->get_config());
}

static void mqtt_ml_dtor(Inspector* p)
{
    assert(p);
    delete p;
}

static const InspectApi mqtt_ml_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MQTT_ML_NAME,
        MQTT_ML_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__ANY_IP,
    nullptr,  // buffers
    nullptr,  // service
    nullptr,  // pinit
    nullptr,  // pterm
    nullptr,  // tinit
    nullptr,  // tterm
    mqtt_ml_ctor,
    mqtt_ml_dtor,
    nullptr,  // ssn
    nullptr   // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_mqtt_ml[] =
#endif
{
    &mqtt_ml_api.base,
    nullptr
};
