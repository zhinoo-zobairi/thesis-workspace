set( FILE_LIST
    mqtt.cc
    mqtt.h
    mqtt_events.h
    mqtt_ml.cc
    mqtt_ml.h
    mqtt_ml_module.cc
    mqtt_ml_module.h
    mqtt_module.cc
    mqtt_module.h
    mqtt_paf.cc
    mqtt_paf.h
    ips_mqtt_topic.cc
    ips_mqtt_payload.cc
)

if (STATIC_INSPECTORS)
    add_library(mqtt OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(mqtt inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)