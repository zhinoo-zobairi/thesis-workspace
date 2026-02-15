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

// mqtt_ml.h author Zhinoo Zobairi
// MQTT ML-based anomaly detection inspector

#ifndef MQTT_ML_H
#define MQTT_ML_H

#include "framework/inspector.h"
#include "mqtt_ml_module.h"

#ifdef HAVE_TFLITE
#include "tensorflow/lite/c/c_api.h"
#endif

class MqttML : public snort::Inspector
{
public:
    MqttML(const MqttMLConfig& c) : conf(c) {}
    ~MqttML() override;

    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet*) override {}  // We use DataBus, not packet eval
    bool configure(snort::SnortConfig*) override;

    const MqttMLConfig& get_config() const
    { return conf; }

    // TF Lite model access for the handler
    float run_model(const float* input, float* output, size_t num_features) const;
    bool is_model_loaded() const { return model_loaded; }
    float get_threshold() const { return threshold; }

private:
    MqttMLConfig conf;
    bool model_loaded = false;
    float threshold = 0.5f;

    bool load_model();
    bool load_threshold();

#ifdef HAVE_TFLITE
    TfLiteModel* model = nullptr;
    TfLiteInterpreter* interpreter = nullptr;
    TfLiteInterpreterOptions* options = nullptr;
#endif
};

#endif
