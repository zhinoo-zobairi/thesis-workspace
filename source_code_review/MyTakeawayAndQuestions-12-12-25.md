## Takeaways
-  `http_api.h/.cc`: This is where we register our plugin to Snort: **the registration point**
- `sin_http[]` lists all HTTP-related plugins = **a table of contents pointing to all HTTP-related plugins** 
    - Plugin #1, main inspector (`&HttpApi::http_api.base`) = A POINTER to the STRUCT `InspectApi` (not an object!)
    - Plugins #2-26, many rule options (`ips_http_uri`, `ips_http_body`, etc.) = **Each rule option is a separate plugin** that happen to be rule options that work WITH that inspector
````c++
// In http_api.cc:

const BaseApi* sin_http[] = 
{
    &HttpApi::http_api.base,  // Plugin #1: The pointer to the main inspector
    ips_http_uri,              // Plugin #2: Separate, independent plugin
    ips_http_client_body,      // Plugin #3: Separate, independent plugin
    ips_http_cookie,           // Plugin #4: Separate, independent plugin
    // ... 22 more separate plugins
    nullptr
};
````

- `sin_http[]` doesn't contain the rules themselves, it contains pointers to the plugins that implement rule options, for example a pointer to `ips_http_uri`. The `ips_http_uri` is defined in ONE BIG file: `ips_http_buffer.cc`, which contains all 17 plugins; they're all related "buffer" plugins for rule matching:
    - That file says: "When someone writes `http_uri` in a rule, call this function"

- MODULE (config parser)
   - http_**mod**_ctor() creates **HttpModule**
   - HttpModule **reads snort.lua config**
   - HttpModule validates and stores settings

- INSPECTOR (packet processor)  
   - http_ctor(module) creates HttpInspect
   - http_ctor uses settings FROM the module
   - HttpInspect processes packets

- CLEANUP
   - http_dtor() destroys HttpInspect
   - http_mod_dtor() destroys HttpModule

---
`http_flow_data.c` & `http_flow_data.h`
- Since HTTP is stateful, we need to remember what we've seen and what comes next. `HttpFlowData` stores state FOR EACH CONNECTION, so that `HttpInspect` can use it to track parsing progress.

- `http_flow_data` inherits from the Snort's public FlowData class. FlowData already provides: attach to flow, unique ID system, lifecycle. We just add: HTTP-specific fields (what section expected, body length, etc.)
```c++
// Constructor called when first an HTTP packet on a new connection arrives
HttpFlowData(snort::Flow* flow, const HttpParaList* params_);
// and Deconstructor, called when connection closes
~HttpFlowData() override; // Decrement concurrent sessions

```
- `inspector_id`: Unique ID for HTTP inspector's flow data, Snort uses this to find our data attached to a flow

- "friend" grants another class access to private members
     - WHY SO MANY FRIENDS?
       - HttpFlowData is the central state storage
       - Many classes need to read/write this state
       - Instead of 100 getter/setter methods, we use friends
       - Trade-off: Less encapsulation, but simpler code
- `HTTPCutter` that decides where to cut the TCP Byte Stream
## ??? Do we need a cutter as well for MQTT???

- **HttpTransaction** is a C++ object that stores: The request line, the response status, headers for both directions, body data, infractions/errors found during parsing. It is only created when we have enough data to start processing a message.

- Infractions are associated with a specific message and are stored in the transaction for that message = Temporary home for problems found before transaction exists. Created on Heap, returns pointer. Infractions track protocol violations and anomalies.
```
TIME 1: First TCP packet arrives with "GET /path HTTP/1.1\r\n..."
        │
        ├── StreamSplitter::scan() runs
        │   └── Looks for end of request line
        │   └── Might find problems! (bad characters, too long, etc.)
        │   └── WHERE TO PUT INFRACTIONS? No transaction yet!
        │
        └── Transaction doesn't exist until we have enough data

TIME 2: More data arrives, StreamSplitter says "request line complete"
        │
        ├── Inspector::eval() runs
        │   └── Creates HttpTransaction via attach_my_transaction()
        │   └── NOW we have a transaction!
        │
        └── But infractions were already found in TIME 1...
```
## ??? JAVASCRIPT NORMALIZATION STATE ???
- Discard list (transactions waiting for deletion) is just Walking linked list and deleting each node:
```c++
    while (discard_list != nullptr)
    {
        HttpTransaction* tmp = discard_list;
        discard_list = discard_list->next;
        delete tmp;
    }
```
## ??? HALF_RESET: Reset one direction after message completes ???
