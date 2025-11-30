┌─────────────────────────────────────────────────────────────┐
│                      Snort Core                             │
│                                                             │
│   Looks for plugins that provide an "InspectApi" struct     │
└─────────────────────────────────────────────────────────────┘
                            ↓
                    Plugin registers via
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                     InspectApi struct                       │
│                                                             │
│   - name: "http_inspect"                                    │
│   - type: service inspector                                 │
│   - ctor: function to create inspector instance             │
│   - dtor: function to destroy inspector instance            │
│   - init: initialization function                           │
│   - etc.                                                    │
└─────────────────────────────────────────────────────────────┘
                            ↓
                    ctor() returns
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   Inspector class                           │
│                   (e.g., HttpInspect)                       │
│                                                             │
│   - eval(Packet*): process a packet                         │
│   - get_buf(...): return data for rules                     │
│   - get_splitter(...): return stream splitter               │
│   - etc.                                                    │
└─────────────────────────────────────────────────────────────┘


## Every inspector follows this pattern

| Component | HTTP | Max's IPv6 |  MQTT (future) |
|-----------|------|------------|---------------------|
| API file | `http_api.h/.cc` | `ipv6_api.h/.cc` (probably) | `mqtt_api.h/.cc` |
| Inspector file | `http_inspect.h/.cc` | `ipv6_inspect.h/.cc` (probably) | `mqtt_inspect.h/.cc` |
| Registration struct | `InspectApi http_api` | `InspectApi ipv6_api` | `InspectApi mqtt_api` |
| Inspector class | `HttpInspect` | `IPv6Inspect` | `MqttInspect` |

Same pattern, different protocols.


┌─────────────────────────────────────────────────────────────────────────┐
│                           SNORT CORE                                    │
│                                                                         │
│  At startup, looks for plugin arrays like sin_http[]                    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  http_api.cc: sin_http[] array                                          │
│                                                                         │
│  Contains: &HttpApi::http_api.base, ips_http_uri, ips_http_body, ...    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  http_api.h/cc: HttpApi::http_api (InspectApi struct)                   │
│                                                                         │
│  Fields:                                                                │
│    - name: "http_inspect"                                               │
│    - type: IT_SERVICE                                                   │
│    - ctor: http_ctor → creates HttpInspect                              │
│    - init: http_init → one-time setup                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                          http_ctor() called
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  http_inspect.h: class HttpInspect                                      │
│                                                                         │
│  Key methods:                                                           │
│    - eval(Packet*) → main entry, processes HTTP packets                 │
│    - get_buf(...) → provides data to rules                              │
│    - get_splitter() → returns TCP→HTTP splitter                         │
│    - get_pub_id() → for publishing body events                          │
│                                                                         │
│  Key members:                                                           │
│    - splitter[2] → client/server stream splitters                       │
│    - params → configuration                                             │
│    - pub_id → event publication ID                                      │
└─────────────────────────────────────────────────────────────────────────┘