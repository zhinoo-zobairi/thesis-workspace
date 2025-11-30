### `http_api.h/.cc`: **Plugin registration**

- **Header files (`.h`)** = the **interface/structure**: What classes exist, What methods are available, What data members a class has, How things connect.

- **Source files (`.cc`)** = the **implementation/details**: How each method actually works, The logic inside functions

This file defines **how Snort finds and loads the HTTP inspector**.

Key piece:

```cpp
// This struct tells Snort: "Here's an inspector called http_inspect"
static const InspectApi http_api = {
    .name = "http_inspect",
    .type = IT_SERVICE,
    .ctor = http_ctor,    // Function that creates HttpInspect
    .dtor = http_dtor,    // Function that destroys HttpInspect
    .init = http_init,    // Called once at startup
    // ...more fields
};
```

Without this, Snort doesn't know your inspector exists.

### `http_inspect.h/.cc` — **Inspector implementation**

This is the **actual inspector class** that does the work.

Key piece:

```cpp
class HttpInspect : public Inspector {
    // Called when a packet arrives
    void eval(Packet* p) override;
    
    // Called when rules need HTTP data (e.g., http_uri, http_body)
    bool get_buf(...) override;
    
    // Returns the stream splitter for TCP reassembly
    StreamSplitter* get_splitter(bool c2s) override;
};
```


---

```
http_api.h + http_inspect.h
       ↓
       Understand: "What is an inspector? How is it registered?"
       ↓
Flow data, splitters, message sections, events
       ↓
       Understand: "How does the inspector actually process data?"
       ↓
Max's IPv6 plugin
       ↓
       Understand: "How did someone else build a plugin?"
       ↓
Meeting: I can ask informed questions about MQTT plugin design
```
