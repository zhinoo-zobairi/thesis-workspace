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
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
//--------------------------------------------------------------------------

// mqtt_ml.cc author Zhinoo Zobairi
// MQTT ML-based anomaly detection inspector implementation

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mqtt_ml.h"

#include <cassert>
#include <cmath>
#include <cstring>
#include <fstream>
#include <string>

#include "detection/detection_engine.h"
#include "framework/data_bus.h"
#include "log/messages.h"
#include "profiler/profiler.h"

#include "mqtt_events.h"

using namespace snort;

//--------------------------------------------------------------------------
// Feature Vector Constants and Normalization
//--------------------------------------------------------------------------

// Number of features in our feature vector
// This must match what the ML model expects!
static constexpr size_t MQTT_ML_NUM_FEATURES = 28;

// Max values for log normalization of unbounded features
// These are tuned based on expected traffic patterns
static constexpr float MAX_REMAINING_LEN = 268435455.0f;  // MQTT max (4 bytes, 7 bits each)
static constexpr float MAX_KEEP_ALIVE = 65535.0f;         // 2 bytes
static constexpr float MAX_STRING_LEN = 65535.0f;         // MQTT string length is 2 bytes
static constexpr float MAX_PAYLOAD_LEN = 268435455.0f;    // Same as remaining_len
static constexpr float MAX_TIME_DELTA_US = 60000000.0f;   // 60 seconds in microseconds
static constexpr float MAX_FAILED_AUTH_RATE = 100.0f;     // 100 failures/sec is extreme
static constexpr float MAX_PKT_COUNT = 10000.0f;          // Packets per flow

//--------------------------------------------------------------------------
// Normalization Helper Functions
//--------------------------------------------------------------------------

// Min-max normalization: (value - min) / (max - min)
// Result is in range [0.0, 1.0]
static inline float normalize_minmax(float value, float min_val, float max_val)
{
    if (max_val <= min_val)
        return 0.0f;
    float result = (value - min_val) / (max_val - min_val);
    // Clamp to [0, 1] in case value is outside expected range
    if (result < 0.0f) result = 0.0f;
    if (result > 1.0f) result = 1.0f;
    return result;
}

// Log normalization: log(value + 1) / log(max + 1)
// Good for unbounded values that can vary by orders of magnitude
// +1 prevents log(0) which is undefined
static inline float normalize_log(float value, float max_val)
{
    if (value <= 0.0f)
        return 0.0f;
    if (max_val <= 0.0f)
        return 0.0f;
    float log_val = std::log(value + 1.0f);
    float log_max = std::log(max_val + 1.0f);
    float result = log_val / log_max;
    if (result > 1.0f) result = 1.0f;
    return result;
}

// Boolean/flag to float: 0 → 0.0, non-zero → 1.0
static inline float normalize_flag(uint8_t value)
{
    return value ? 1.0f : 0.0f;
}

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
    
    // Build feature vector from event (fills array with normalized features)
    // Returns actual number of features written
    size_t build_feature_vector(const MqttFeatureEvent& fe, float* features, size_t max_features);
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
    
    if (!inspector.is_model_loaded())
        return;
    
    // Build normalized feature vector
    float features[MQTT_ML_NUM_FEATURES];
    size_t num_features = build_feature_vector(fe, features, MQTT_ML_NUM_FEATURES);
    
    // Run autoencoder: feed input, get reconstructed output
    float output[MQTT_ML_NUM_FEATURES];
    float rc = inspector.run_model(features, output, num_features);
    
    if (rc < 0.0f)
        return;  // Model error
    
    // Compute Mean Squared Error between input and reconstruction
    float mse = 0.0f;
    for (size_t i = 0; i < num_features; i++)
    {
        float diff = features[i] - output[i];
        mse += diff * diff;
    }
    mse /= static_cast<float>(num_features);
    
    // Compare MSE (reconstruction error) against threshold
    // High MSE = anomaly (model can't reconstruct what it hasn't seen)
    if (mse >= inspector.get_threshold())
    {
        mqtt_ml_stats.anomalies_detected++;
        DetectionEngine::queue_event(MQTT_ML_GID, MQTT_ML_SID);
    }
}

size_t MqttFeatureHandler::build_feature_vector(const MqttFeatureEvent& fe, 
                                                 float* features, 
                                                 size_t max_features)
{
    // Ensure we don't overflow the buffer
    if (max_features < MQTT_ML_NUM_FEATURES)
        return 0;
    
    size_t idx = 0;
    
    // ========== Fixed Header Fields ==========
    
    // Feature 0: msg_type (bounded 1-14) → min-max
    features[idx++] = normalize_minmax(static_cast<float>(fe.msg_type), 1.0f, 14.0f);
    
    // Feature 1: dup_flag (boolean) → one-hot
    features[idx++] = normalize_flag(fe.dup_flag);
    
    // Feature 2: qos (bounded 0-2) → min-max
    features[idx++] = normalize_minmax(static_cast<float>(fe.qos), 0.0f, 2.0f);
    
    // Feature 3: retain (boolean) → one-hot
    features[idx++] = normalize_flag(fe.retain);
    
    // Feature 4: remaining_len (unbounded) → log normalization
    features[idx++] = normalize_log(static_cast<float>(fe.remaining_len), MAX_REMAINING_LEN);
    
    // ========== CONNECT Fields ==========
    
    // Feature 5: protocol_version (bounded 3-5) → min-max
    // Note: version 3=MQTT 3.1, 4=MQTT 3.1.1, 5=MQTT 5.0
    features[idx++] = normalize_minmax(static_cast<float>(fe.protocol_version), 3.0f, 5.0f);
    
    // Feature 6-11: Connection flags (booleans) → one-hot
    features[idx++] = normalize_flag(fe.conflag_clean_session);  // Feature 6
    features[idx++] = normalize_flag(fe.conflag_will_flag);      // Feature 7
    features[idx++] = normalize_minmax(static_cast<float>(fe.conflag_will_qos), 0.0f, 2.0f);  // Feature 8
    features[idx++] = normalize_flag(fe.conflag_will_retain);    // Feature 9
    features[idx++] = normalize_flag(fe.conflag_passwd);         // Feature 10
    features[idx++] = normalize_flag(fe.conflag_uname);          // Feature 11
    
    // Feature 12: keep_alive (unbounded but typically 0-65535) → log normalization
    features[idx++] = normalize_log(static_cast<float>(fe.keep_alive), MAX_KEEP_ALIVE);
    
    // Feature 13-17: String lengths (unbounded) → log normalization
    features[idx++] = normalize_log(static_cast<float>(fe.client_id_len), MAX_STRING_LEN);   // Feature 13
    features[idx++] = normalize_log(static_cast<float>(fe.username_len), MAX_STRING_LEN);   // Feature 14
    features[idx++] = normalize_log(static_cast<float>(fe.passwd_len), MAX_STRING_LEN);     // Feature 15
    features[idx++] = normalize_log(static_cast<float>(fe.will_topic_len), MAX_STRING_LEN); // Feature 16
    features[idx++] = normalize_log(static_cast<float>(fe.will_msg_len), MAX_STRING_LEN);   // Feature 17
    
    // ========== CONNACK Fields ==========
    
    // Feature 18: conack_return_code (bounded 0-5 for MQTT 3.1.1) → min-max
    features[idx++] = normalize_minmax(static_cast<float>(fe.conack_return_code), 0.0f, 5.0f);
    
    // Feature 19: conack_session_present (boolean) → one-hot
    features[idx++] = normalize_flag(fe.conack_session_present);
    
    // ========== PUBLISH Fields ==========
    
    // Feature 20: topic_len (unbounded) → log normalization
    features[idx++] = normalize_log(static_cast<float>(fe.topic_len), MAX_STRING_LEN);
    
    // Feature 21: payload_len (unbounded) → log normalization
    features[idx++] = normalize_log(static_cast<float>(fe.payload_len), MAX_PAYLOAD_LEN);
    
    // Feature 22: msg_id (bounded 0-65535) → log normalization
    features[idx++] = normalize_log(static_cast<float>(fe.msg_id), 65535.0f);
    
    // ========== Timing Features ==========
    
    // Feature 23: time_delta_us (unbounded) → log normalization
    // This is time since first packet in flow (microseconds)
    features[idx++] = normalize_log(static_cast<float>(fe.time_delta_us), MAX_TIME_DELTA_US);
    
    // Feature 24: time_relative_us (same as delta, included for compatibility)
    features[idx++] = normalize_log(static_cast<float>(fe.time_relative_us), MAX_TIME_DELTA_US);
    
    // ========== Brute Force Detection Features ==========
    
    // Feature 25: failed_auth_per_second (unbounded) → log normalization
    features[idx++] = normalize_log(fe.failed_auth_per_second, MAX_FAILED_AUTH_RATE);
    
    // Feature 26: failed_auth_count (unbounded) → log normalization
    features[idx++] = normalize_log(static_cast<float>(fe.failed_auth_count), 100.0f);
    
    // ========== Flow Statistics ==========
    
    // Feature 27: pkt_count (unbounded) → log normalization
    features[idx++] = normalize_log(static_cast<float>(fe.pkt_count), MAX_PKT_COUNT);
    
    // Verify we wrote exactly the expected number of features
    assert(idx == MQTT_ML_NUM_FEATURES);
    
    return idx;
}

//--------------------------------------------------------------------------
// MqttML inspector methods — TF Lite model lifecycle
//--------------------------------------------------------------------------

MqttML::~MqttML()
{
#ifdef HAVE_TFLITE
    if (interpreter)
        TfLiteInterpreterDelete(interpreter);
    if (options)
        TfLiteInterpreterOptionsDelete(options);
    if (model)
        TfLiteModelDelete(model);
#endif
}

bool MqttML::load_model()
{
#ifdef HAVE_TFLITE
    if (conf.model_path.empty())
    {
        LogMessage("mqtt_ml: no model_path configured, ML detection disabled\n");
        return false;
    }

    model = TfLiteModelCreateFromFile(conf.model_path.c_str());
    if (!model)
    {
        WarningMessage("mqtt_ml: failed to load model from '%s'\n", conf.model_path.c_str());
        return false;
    }

    options = TfLiteInterpreterOptionsCreate();
    TfLiteInterpreterOptionsSetNumThreads(options, 1);

    interpreter = TfLiteInterpreterCreate(model, options);
    if (!interpreter)
    {
        WarningMessage("mqtt_ml: failed to create TF Lite interpreter\n");
        return false;
    }

    if (TfLiteInterpreterAllocateTensors(interpreter) != kTfLiteOk)
    {
        WarningMessage("mqtt_ml: failed to allocate tensors\n");
        return false;
    }

    LogMessage("mqtt_ml: model loaded from '%s'\n", conf.model_path.c_str());
    return true;
#else
    WarningMessage("mqtt_ml: Snort was compiled without TF Lite support (HAVE_TFLITE)\n");
    return false;
#endif
}

bool MqttML::load_threshold()
{
    if (!conf.threshold_path.empty())
    {
        std::ifstream f(conf.threshold_path);
        if (f.is_open())
        {
            double val;
            if (f >> val)
            {
                threshold = static_cast<float>(val);
                LogMessage("mqtt_ml: threshold loaded from '%s': %e\n",
                    conf.threshold_path.c_str(), threshold);
                return true;
            }
        }
        WarningMessage("mqtt_ml: failed to read threshold from '%s', using configured value\n",
            conf.threshold_path.c_str());
    }

    // Fall back to configured anomaly_threshold
    threshold = static_cast<float>(conf.anomaly_threshold);
    return true;
}

float MqttML::run_model(const float* input, float* output, size_t num_features) const
{
#ifdef HAVE_TFLITE
    if (!interpreter)
        return -1.0f;

    // Copy input features to input tensor
    TfLiteTensor* input_tensor = TfLiteInterpreterGetInputTensor(interpreter, 0);
    if (!input_tensor)
        return -1.0f;

    TfLiteTensorCopyFromBuffer(input_tensor, input, num_features * sizeof(float));

    // Run inference
    if (TfLiteInterpreterInvoke(interpreter) != kTfLiteOk)
        return -1.0f;

    // Copy output (reconstructed features) from output tensor
    const TfLiteTensor* output_tensor = TfLiteInterpreterGetOutputTensor(interpreter, 0);
    if (!output_tensor)
        return -1.0f;

    TfLiteTensorCopyToBuffer(output_tensor, output, num_features * sizeof(float));
    return 0.0f;  // Success
#else
    (void)input;
    (void)output;
    (void)num_features;
    return -1.0f;
#endif
}

void MqttML::show(const SnortConfig*) const
{
    ConfigLogger::log_value("anomaly_threshold", conf.anomaly_threshold);
    ConfigLogger::log_flag("enabled", conf.enabled);
    if (!conf.model_path.empty())
        ConfigLogger::log_value("model_path", conf.model_path.c_str());
    if (!conf.threshold_path.empty())
        ConfigLogger::log_value("threshold_path", conf.threshold_path.c_str());
}

bool MqttML::configure(SnortConfig*)
{
    // Load TF Lite model
    if (conf.enabled)
    {
        model_loaded = load_model();
        load_threshold();

        if (model_loaded)
            LogMessage("mqtt_ml: ML anomaly detection active (threshold=%e)\n", threshold);
        else
            LogMessage("mqtt_ml: ML model not loaded, events will be counted but not scored\n");
    }

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
