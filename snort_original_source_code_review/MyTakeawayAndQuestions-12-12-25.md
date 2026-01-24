# HTTP Inspector
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
````
                        CONNECTION STARTS
═══════════════════════════════════════════════════════════════════════

TCP SYN         →  Client sends SYN
TCP SYN/ACK     →  Server responds
TCP ACK         →  Connection established!
                        │
                        ▼
                   Snort creates a Flow object
                        │
                        ▼
        First HTTP data arrives (e.g., "GET /page"), no FlowData yet
                            │
                            ▼
     ┌──────────────────────────────────────────────────────────────┐
     │          HttpStreamSplitter::scan() is called                │
     │                        │                                     │
     │                        ▼                                     │
     │          "Do we have HttpFlowData for this flow?"            │
     │                        │                                     │
     │              NO → CREATE IT!                                 │
     │                        │                                     │
     │                        ▼                                     │
     │          HttpFlowData() constructor runs                     │
     │          (attached to Flow object)                           │
     │                        │                                     │
     │                        ▼                                     │
     │          StreamSplitter parses HTTP boundaries               │
     │          (finds end of headers, content-length, etc.)        │
     └──────────────────────────────────────────────────────────────┘
                                │
                                ▼
     ┌──────────────────────────────────────────────────────────────┐
     │       HttpStreamSplitter::reassemble() is called             │
     │       (assembles complete HTTP section)                      │
     └──────────────────────────────────────────────────────────────┘
                                │
                                ▼
     ┌──────────────────────────────────────────────────────────────┐
     │  HttpInspect::eval() is called, retrieves existing FlowData  │
     │                   asserts if null                            │
     │                        │                                     │
     │                        ▼                                     │
     │          http_get_flow_data(flow)                            │
     │                        │                                     │
     │          FlowData MUST exist! (assert if null)               │
     │          (StreamSplitter already created it)                 │
     │                        │                                     │
     │                        ▼                                     │
     │          Process the HTTP message section                    │
     └──────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════
                     CONNECTION IS ALIVE
              (seconds, minutes, or hours later...)
═══════════════════════════════════════════════════════════════════════

Many HTTP transactions happen:
  GET /page1 → 200 OK     (Transaction 1)
  GET /page2 → 200 OK     (Transaction 2)
  POST /form → 302        (Transaction 3)
  
HttpFlowData lives through ALL of these
(Transactions are created/deleted, but FlowData persists)

═══════════════════════════════════════════════════════════════════════
                        CONNECTION ENDS
═══════════════════════════════════════════════════════════════════════

TCP FIN         →  "I'm done sending"
TCP FIN/ACK     →  "OK, me too"
   (or TCP RST  →  "Connection forcefully reset!")
                        │
                        ▼
              Snort sees connection is closed
                        │
                        ▼
              Flow object is being destroyed
                        │
                        ▼
              Flow iterates its FlowDataStore
              (may contain multiple FlowData from different inspectors)
                        │
                        ▼
              delete flowData;  // for each attached FlowData
                        │
                        ▼
              ~HttpFlowData() destructor runs
                        │
                        ├── Cleans up discard_list, all attached FlowData
                        ├── Deletes remaining transactions
                        └── Decrements session counter
````

### Why Flow Has Multiple FlowData Objects

A single TCP connection (Flow) can be processed by **multiple inspectors**, each with its own FlowData. HTTP, however, only creates ONE FlowData! Those multiple FlowData types are from different inspectors, not all from HTTP:

```
                    ┌─────────────────────────────────────────┐
                    │              One Flow (TCP conn)        │
                    │                                         │
                    │  FlowDataStore (list of FlowData):      │
                    │  ┌─────────────────────────────────────┐│
                    │  │ HttpFlowData   (id=42)              ││
                    │  │ FileFlowData   (id=17)              ││
                    │  │ SSLFlowData    (id=23)  (if HTTPS)  ││
                    │  │ StreamFlowData (id=5)               ││
                    │  └─────────────────────────────────────┘│
                    └─────────────────────────────────────────┘
```
## ??? What to do for the MQQT Inspector ???
- MQTT runs over TCP (Port 1883, or 8883 for TLS).
````
┌─────────────────────────────────────────┐
│            MQTT Protocol                │
├─────────────────────────────────────────┤
│            TCP (port 1883)              │
├─────────────────────────────────────────┤
│            IP                           │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│              MQTT TCP Connection (Flow)                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   FlowDataStore:                                                │
│   ┌─────────────────┬─────────────────┬───────────────────────┐ │
│   │ FlowData        │ Created by      │ Who writes it?        │ │
│   ├─────────────────┼─────────────────┼───────────────────────┤ │
│   │ StreamFlowData  │ Stream TCP      │ Snort (automatic)     │ │
│   │ MqttFlowData    │ MqttInspect     │ YOU! ← only this one  │ │
│   └─────────────────┴─────────────────┴───────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
````

- Each FlowData has a unique ID. When HttpInspect needs its FlowData:

```cpp
// Gets ONLY HttpFlowData from the list, using its unique ID
http_get_flow_data(flow)  // → flow->get_flow_data(HttpFlowData::inspector_id)
```
- `inspector_id`: Unique ID for HTTP inspector's flow data, Snort uses this to find our data attached to a flow
  - Each inspector class has a static unique ID (e.g., HttpFlowData::inspector_id = 42)
  - Flow stores multiple FlowData in a FlowDataStore (one per active inspector)
  - Inspectors retrieve their FlowData with: `flow->get_flow_data(HttpFlowData::inspector_id)`

- "friend" grants another class access to private members
  - WHY SO MANY FRIENDS?
    - HttpFlowData is the central state storage
    - Many classes need to read/write this state
    - Instead of 100 getter/setter methods, we use friends
    - Trade-off: Less encapsulation, but simpler code

- `HttpCutter` decides where to cut the TCP Byte Stream by:
```c++
class HttpCutter {
    // State machine for finding header boundaries
    // - Scan byte-by-byte for \r\n\r\n
    // - Handle partial data across packets
    // - Track if we're in headers vs body
    
    // Body length determination
    // - Parse Content-Length header
    // - Handle chunked encoding (multiple chunks!)
    // - Handle connection close
};
```

## ??? Do we need a cutter as well for MQTT ???

````
┌──────────────────────────────────────────────────────────────┐
│                    MQTT Packet                               │
├─────────────┬──────────────────┬─────────────────────────────┤
│ Fixed Header│ Remaining Length │ Variable Header + Payload   │
│  (1 byte)   │   (1-4 bytes)    │   (N bytes)                 │
├─────────────┴──────────────────┴─────────────────────────────┤
│                                                              │
│  Byte 0:    [Packet Type (4 bits)][Flags (4 bits)]           │
│  Byte 1-4:  Variable-length integer (tells us EXACTLY        │
│             how many more bytes to read!)                    │
│                                                              │
└──────────────────────────────────────────────────────────────┘

MQTT:                              HTTP:
┌─────────────┐                    ┌─────────────────────────────┐
│ Type │ Len  │ Payload            │ GET /page HTTP/1.1\r\n      │
└──────┴──────┘                    │ Host: example.com\r\n       │
   ↑                               │ Content-Type: text/html\r\n │
                                   │ Content-Length: 42\r\n      │
   Byte 1-4 tells us               │ \r\n                        │
   EXACTLY how much                │ <body here>                 │
   more to read!                   └─────────────────────────────┘
                                      ↑
                                      We must:
                                      1. Find \r\n\r\n (end of headers)
                                      2. Parse headers to find Content-Length
                                      3. THEN we know body size
                                      
                                      OR it's chunked... even worse!
````

- `garbage_collect()` operates on `this->discard_list`: a member variable of **HttpFlowData**
  - It removes transactions that were processed by inspector to free up memory

````
HttpFlowData object:
┌──────────────────────────────────────────────────────────-┐
│                                                           │
│  discard_list ──► Trans1 ──► Trans2 ──► Trans3 ──► nullptr│
│       │                                                   │
│       └── This IS the list head!                          │
│                                                           │
└──────────────────────────────────────────────────────────-┘
````
- **HttpTransaction** is a C++ object that stores: The request line, the response status, headers for both directions, body data, infractions/errors found during parsing. It is only created when we have enough data to start processing a message => One HTTP transaction = one request + its matching response:
    - HttpFlowData = per-CONNECTION state (can have multiple transactions)
    - HttpTransaction = per-REQUEST/RESPONSE state

- Infractions are associated with a specific message and are stored in the transaction for that message = Temporary home for problems found before transaction exists. Created on Heap, returns pointer. Infractions track protocol violations and anomalies.

## ??? Do we need infractions as well for MQTT???

```
TCP packets arrive
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  STREAMSPLITTER PHASE (scanning)                            │
│                                                             │
│  - Looking for message boundaries                           │
│  - Transaction does NOT exist                               │
│  - Infractions stored in FlowData->infractions[]            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
       │
       │ scan() returns FLUSH (section boundary found!)
       ▼
┌─────────────────────────────────────────────────────────────┐
│  INSPECTOR PHASE (processing)                               │
│                                                             │
│  1. attach_my_transaction() called                          │
│  2. Transaction CREATED (for SEC_REQUEST)                   │
│  3. Infractions MOVED: FlowData → Transaction               │
│  4. Section is parsed and analyzed                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```
## ??? JAVASCRIPT NORMALIZATION STATE ???
- Discard list (transactions waiting for deletion) is just walking a linked list and deleting each node:
```c++
    while (current != nullptr)
    {
        HttpTransaction* tmp = current->next;
        delete current;
        current = tmp;
    }
```
## ??? HALF_RESET: Reset one direction after message completes ???

---
`http_transaction.h` & `http_transaction.h`:
````
One TCP Connection (Flow):
   ┌────────────────────────────────────────────────────────────┐
   │ Transaction 1: GET /page1.html  →  200 OK + HTML content   │
   │ Transaction 2: GET /style.css   →  200 OK + CSS content    │
   │ Transaction 3: POST /submit     →  302 Redirect            │
   └────────────────────────────────────────────────────────────┘
````
- HTTP PIPELINING AND TRANSACTIONS:
   - Without pipelining (normal):

        - Request1 → Response1 → Request2 → Response2
     (One transaction at a time)

   - With pipelining:

        - Request1 → Request2 → Request3 → Response1 → Response2 → Response3
     (Multiple transactions in flight, must match requests to responses)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ONE TCP CONNECTION (Flow)                        │
│                         │                                           │
│                         ▼                                           │
│              ┌─────────────────────┐                                │
│              │    HttpFlowData     │  ← ONE per connection          │
│              │                     │                                │
│              │  Remembers state    │                                │
│              │  across all packets │                                │
│              │  on this connection │                                │
│              └─────────┬───────────┘                                │
│                        │                                            │
│         ┌──────────────┼──────────────┐                             │
│         ▼              ▼              ▼                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                    │
│  │Transaction 1│ │Transaction 2│ │Transaction 3│                    │
│  │ GET /page1  │ │ GET /page2  │ │ POST /form  │                    │
│  │ → 200 OK    │ │ → 200 OK    │ │ → 302 Redir │                    │
│  └─────────────┘ └─────────────┘ └─────────────┘                    │
│   Transactions come and go; FlowData persists until conn closes     │
└─────────────────────────────────────────────────────────────────────┘
```
````
Timeline:
─────────────────────────────────────────────────────────────────────

1. TCP connection established
   └── Flow created (no FlowData yet)

2. First HTTP data arrives ("GET /page...")
   └── StreamSplitter::scan() creates HttpFlowData
       └── HttpFlowData attached to Flow

3. StreamSplitter finds complete request line section
   └── reassemble() called
       └── eval() called
           └── attach_my_transaction() called
               └── section_type == SEC_REQUEST
                   └── NEW HttpTransaction created! ← HERE!
                       └── Transaction added to pipeline

4. More sections arrive (headers, body, response...)
   └── Each section attached to EXISTING transaction
       └── attach_my_transaction() finds it in pipeline
````
**Infractions:** The Timing Problem

**Problem:** StreamSplitter may find protocol violations BEFORE a Transaction exists.
````
┌─────────────────────────────────────────────────────────────────┐
│  StreamSplitter::scan() is parsing...                           │
│                                                                 │
│  "GET /page\x00HTTP/1.1\r\n"                                    │
│              ↑                                                  │
│         NULL byte! That's a violation!                          │
│                                                                 │
│  But wait... Transaction doesn't exist yet!                     │
│  (Transaction is created in eval(), we're still in scan())      │
│                                                                 │
│  Where do we store this infraction?                             │
└─────────────────────────────────────────────────────────────────┘
````

- `attach_my_transaction()` Cases: The function handles **three main cases**:

    - **CASE 1 - New Request (SEC_REQUEST)**: Handles the old transaction[CLIENT] before creating a new one.
        - 1a: response_seen is true → soft delete (response owns it):

            Timeline:
            1. Request #1 starts           (transaction[CLIENT] created)
            2. Request #1 still sending... (body is large)
            3. Response #1 arrives!        (server is fast, sets response_seen = true)
                                        (transaction[CLIENT] now has shared_ownership)
            4. Request #1 finishes
            5. Request #2 arrives          ← WE ARE HERE in CASE 1

                When you see `response_seen == true` in CASE 1, it tells you:
                > *The response side already grabbed this transaction. Don't delete it for real, just let go of it!*
        - 1b: pipeline broken → just delete
        - 1c: normal pipelining → push to pipeline queue
  
    - **CASE 2 - Second Response (after 1xx)**: When second_response_expected is true, archive the old
status/headers and reuse the same transaction. This handles 100 Continue followed by 200 OK.

    - **CASE 3 - New Response (SEC_STATUS)**: Finds matching request transaction for this response.
        - 3a: pipeline underflow → create orphan transaction
        - 3b: pipeline has items → pop from pipeline
        - 3b-i: pipeline empty, no usable request → underflow, create orphan
        - 3b-ii: pipeline empty, request finished → take transaction[CLIENT]
        - 3b-iii: pipeline empty, request in progress → share ownership

            > *The pipeline acts as a **FIFO** queue: requests push completed transactions, responses pull matching ones. Shared ownership handles parallel processing when response starts before request finishes. Infractions are moved from FlowData (temporary storage) to Transaction (permanent home).*

---
`http_stream_splitter.h/.cc`
```
TCP gives you:     "GET /pa"  "ge HTT"  "P/1.1\r\n"  "Host: ex"  "ample.com\r\n\r\n"
                      ↑          ↑          ↑            ↑            ↑
                   packet 1   packet 2   packet 3    packet 4     packet 5

HTTP needs:        "GET /page HTTP/1.1\r\n"  +  "Host: example.com\r\n\r\n"
                   └──── request line ─────┘    └────── headers ──────────┘ 
```
- `scan()`: The heart of the splitter
    - Called by Stream for each TCP segment. Scans bytes looking for
message section boundaries (e.g., \r\n for request line, \r\n\r\n for headers).
- `reassemble()`: Package scanned bytes into a section
    - Called after `scan()` returns **FLUSH**. Takes the accumulated bytes and creates a buffer for the inspector to process.
- `finish()`: Handle connection close
    - Called when TCP connection closes (FIN, RST, or pruning).
    - Handles truncated messages - data that arrived but wasn't flushed.
- `prep_partial_flush()`: Prepare for partial body inspection
    - Used for flow depth and partial inspection. When we've seen enough
body data, we can flush what we have even without a complete section.
- `go_away()`: Cleanup
    - Called when splitter is no longer needed. Empty because HttpStreamSplitter is owned by HttpInspect, not dynamically allocated per-flow.
    
## ??? PDU vs. MTU ???
---
`http_msg_section.h/.cc`: The Base Class for All HTTP Message Parts:

HttpMsgSection is the abstract base class for all HTTP message sections:

- `HttpMsgRequest` (request line)
- `HttpMsgStatus` (status line)
- `HttpMsgHeader` (headers)
- `HttpMsgBody` (body chunks)
- `HttpMsgTrailer` (trailers for chunked encoding)

**Key Methods**:

- analyze()       - Parse/process the section (pure virtual - each subclass implements)

- update_flow()   - Update FlowData state for next section (pure virtual)

- run_detection() - Call Snort's detection engine

- get_classic_buffer() - Provide data for rules like `http_uri`, `http_header`, etc.

**Constructor Flow**:
```
HttpMsgSection(buffer, size, session_data, source_id, ...)
    │
    ├─► Store msg_text (the raw bytes)
    ├─► attach_my_transaction() ← Gets/creates Transaction
    ├─► Copy method_id, version_id, status_code from FlowData
    └─► Save snapshot for detection context
```
---
`http_msg_body.h/.cc`: Body Section Processing: HTTP messages arrive as a stream of bytes. Snort breaks them into logical sections:
- `HttpMsgBody` handles message body chunks.
Bodies can be large, so they arrive in multiple chunks (multiple `HttpMsgBody` objects per transaction).

- Partial Inspection Support: Bodies can be inspected incrementally (partial flush) before the complete body arrives:

    - partial_inspected_octets tracks what's already been seen
    - partial_detect_buffer saves state between partial inspections
    - Prevents evasion by sending huge bodies slowly

````
                    HttpMsgSection (base)
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
 HttpMsgRequest    HttpMsgHeader        HttpMsgBody
 HttpMsgStatus     HttpMsgTrailer              │
       │                   │                   │
       └───────────────────┴──────────────────–┘
                           │
                    All stored in
                   HttpTransaction
````
**Each section**:
1. Gets created with raw bytes from StreamSplitter
2. Attaches to a Transaction
3. analyze() parses/processes its data
4. update_flow() tells FlowData what to expect next
5. run_detection() triggers rule matching
6. Eventually clear() and garbage collected

---
`HttpBodyEvent` & `HttpRequestBodyEvent`:

The HTTP Inspector uses a **publish-subscribe (pub/sub)** system to notify other modules when body data arrives. This allows other inspectors (like AppId, file processing, etc.) to receive HTTP body data without tight coupling.

### Two Body Event Types

| Event Class | Event ID | Purpose | Depth Limit |
|-------------|----------|---------|-------------|
| `HttpBodyEvent` | `BODY` | Generic body data (request or response) | Dynamic (can be requested) |
| `HttpRequestBodyEvent` | `REQUEST_BODY` | Request body only, with more metadata | Static (`BODY_PUBLISH_DEPTH`) |
---
`http_body_event.h/.cc`: A **simple, lightweight** event for publishing body data.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         HttpBodyEvent                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Data Members:                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ http_body_ptr        → Pointer to body data bytes               │    │
│  │ http_body_length     → Number of bytes in this piece            │    │
│  │ is_data_originates_from_client → true=request, false=response   │    │
│  │ last_piece           → true if this is the final piece          │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  Methods:                                                               │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ get_body(length)     → Returns body pointer, sets length        │    │
│  │ is_data_from_client()→ Returns direction                        │    │
│  │ is_last_piece()      → Returns if this is final chunk           │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Use case:** When a subscriber just needs the raw body bytes and direction.

**Key feature:** Supports **dynamic publish depth** - subscribers can request how much body data they want via `HTTP_PUBLISH_LENGTH` event.

---
`http_request_body_event.h/.cc`: A **richer** event specifically for request bodies with more context.

```
┌────────────────────────────────────────────────────────────────────────┐
│                      HttpRequestBodyEvent                              │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  Data Members:                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ http_msg_body       → Pointer to HttpMsgBody object             │   │
│  │ publish_length      → Bytes to publish (may be < body length)   │   │
│  │ msg_offset          → Offset of this piece in total body        │   │
│  │ last_piece          → true if this is the final piece           │   │
│  │ http_flow_data      → Access to flow-level data                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  Methods:                                                              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ get_request_body_data(length, offset)                           │   │
│  │   → Returns raw body bytes (msg_text_new)                       │   │
│  │                                                                 │   │
│  │ get_client_body(length)                                         │   │
│  │   → Returns normalized body (classic_client_body)               │   │
│  │                                                                 │   │
│  │ is_last_request_body_piece()                                    │   │
│  │   → Returns if this is final chunk                              │   │
│  │                                                                 │   │
│  │ is_mime()                                                       │   │
│  │   → Returns true if body has MIME boundary (multipart)          │   │
│  │                                                                 │   │
│  │ get_httpx_stream_id()                                           │   │
│  │   → Returns HTTP/2 stream ID (for multiplexed connections)      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**Use case:** When a subscriber needs:
- Access to both raw and normalized body
- MIME/multipart detection
- HTTP/2 stream identification
- Offset tracking for reassembly

**Key feature:** Uses **static depth limit** (`BODY_PUBLISH_DEPTH`): fixed maximum regardless of subscriber requests.

### Chunked Body Publishing

Bodies can be large, so they're published in **multiple pieces**:

```
Body arrives in chunks:
┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
│ Chunk 1 │  │ Chunk 2 │  │ Chunk 3 │  │ Chunk 4 │
└────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘
     │            │            │            │
     ▼            ▼            ▼            ▼
┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
│ Event 1 │  │ Event 2 │  │ Event 3 │  │ Event 4 │
│ last=F  │  │ last=F  │  │ last=F  │  │ last=T  │
└─────────┘  └─────────┘  └─────────┘  └─────────┘
                                            │
                                            └── Subscriber knows body is complete
```

**Subscribers must:**
1. Accumulate data across multiple events
2. Check `is_last_piece()` to know when body is complete
3. Use `msg_offset` (in HttpRequestBodyEvent) to track position

### Depth Limiting

```
                 0                    BODY_PUBLISH_DEPTH              Body End
                 │                           │                           │
Body data:       ├───────────────────────────┼───────────────────────────┤
                 │◄──── Published ──────────►│◄──── NOT Published ──────►│
                 │                           │                           │
                 │  Events sent with         │  No more events           │
                 │  last_piece = false       │  (or last event has       │
                 │                           │   last_piece = true)      │
```
**Why depth limits?**
- Bodies can be gigabytes (video files, downloads)
```
┌─────────────────────────────────────────────────────────────────┐
│                 HTTP Response (downloading a movie)             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  HTTP/1.1 200 OK                                                │
│  Content-Type: video/mp4                                        │
│  Content-Length: 4,500,000,000   ← 4.5 GB movie file!           │
│                                                                 │
│  [4.5 GB of video data...]                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Without depth limits:
  - Snort would try to buffer 4.5 GB
  - Memory exhaustion → crash
  - Even if it worked, scanning 4.5 GB is slow
  - 99% of attacks are in the **FIRST** few KB anyway. So, most inspection needs only first N bytes.
```
**The Solution**: *Depth Limits*
- `BODY_PUBLISH_DEPTH` is typically a few KB. `HttpRequestBodyEvent` always publishes up to this fixed amount. You can't change it at runtime via configuration.

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  HTTP Body (4.5 GB total)                                       │
│                                                                 │
│  ├──────────────────┼──────────────────────────────────────────▶│
│  │   First 16 KB    │         Rest of body (ignored)            │
│  │  ← INSPECTED →   │                                           │
│  │                  │                                           │
│  └──────────────────┴──────────────────────────────────────────▶│
│        ↑                                                        │
│        │                                                        │
│   request_depth = 16384  (configured in snort.lua)              │
│   response_depth = 16384                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```
---

# NDP Inspector


## Purpose

Detects **IPv6 NDP attacks** including:
- Router Advertisement spoofing
- Neighbor cache poisoning
- DAD (Duplicate Address Detection) attacks
- Redirect attacks
- NDP/MLD flooding

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NDP Inspector Architecture                          │
└─────────────────────────────────────────────────────────────────────────────┘

                              IPv6 Packets
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Indp::eval()                                   │
│                         (Main Entry Point)                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                   │                                         │
│              ┌────────────────────┴────────────────────┐                    │
│              │                                         │                    │
│              ▼                                         ▼                    │
│     ┌─────────────────┐                     ┌─────────────────┐             │
│     │   is_icmp()?    │                     │   parse_nonND() │             │
│     │   ICMPv6 packet │                     │   Regular IPv6  │             │
│     └────────┬────────┘                     │   (topology)    │             │
│              │                              └─────────────────┘             │
│              ▼                                                              │
│     ┌─────────────────┐                                                     │
│     │  parse_icmp6()  │                                                     │
│     │  (ICMPv6 Router)│                                                     │
│     └────────┬────────┘                                                     │
│              │                                                              │
│    ┌─────────┼─────────┬─────────────┬─────────────┐                        │
│    │         │         │             │             │                        │
│    ▼         ▼         ▼             ▼             ▼                        │
│ ┌──────┐ ┌──────┐ ┌──────┐    ┌──────────┐ ┌────────────┐                   │
│ │RA    │ │NS    │ │NA    │    │ Redirect │ │ MLD        │                   │
│ │type  │ │type  │ │type  │    │ type 137 │ │ type 130,  │                   │
│ │134   │ │135   │ │136   │    │          │ │ 143, 151   │                   │
│ └──┬───┘ └──┬───┘ └──┬───┘    └────┬─────┘ └─────┬──────┘                   │
│    │        │        │             │             │                          │
│    ▼        ▼        ▼             ▼             ▼                          │
│ parse_ra parse_ns parse_na  parse_redirect  MLD checks                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                           State Caches                                     │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │  RouterCache    │  │   HostCache     │  │  TmpHostCache   │             │
│  │  (routers)      │  │   (hosts)       │  │  (tmphosts)     │             │
│  ├─────────────────┤  ├─────────────────┤  ├─────────────────┤             │
│  │ MAC → router_   │  │ IP → host_entry │  │ IP → host_entry │             │
│  │      entry      │  │ (verified)      │  │ (pending)       │             │
│  │                 │  │                 │  │                 │             │
│  │ • src_addr      │  │ • mac_addr      │  │ • mac_addr      │             │
│  │ • prefix        │  │ • ip6_addr      │  │ • ip6_addr      │             │
│  │ • flags         │  │ • last_ns/na    │  │ • last_ns/na    │             │
│  │ • prefix_flags  │  │ • advert_count  │  │ • check[3]      │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Detection Events                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  DetectionEngine::queue_event(INDP_GID, SID)                                │
│                                                                             │
│  Alerts:                                                                    │
│  • SID 1:  Spoofed Redirect           • SID 10: DAD Conflict                │
│  • SID 2:  ND Flood                   • SID 11: Spoofed DAD                 │
│  • SID 3:  Router Kill (lifetime<5)   • SID 12: Unsolicited Advertise       │
│  • SID 4:  RA from non-Router         • SID 13: MLD Flood                   │
│  • SID 5:  New Router                 • SID 15: Neighbor Cache Poison       │
│  • SID 6:  Router Flag Changed        • SID 16: MLD Query from non-Router   │
│  • SID 7:  Router Prefix Changed      • SID 17: MLD RA from non-Router      │
│  • SID 8:  New DAD                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Overview – it was a signature-based, no ML ???

### 1. Plugin Structure
Every Snort3 inspector has 3 main components:
```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│    Module    │ ──── │  Inspector   │ ──── │  Plugin API  │
│  (Config)    │      │  (Runtime)   │      │  (Glue)      │
└──────────────┘      └──────────────┘      └──────────────┘
     "WHAT"              "DO IT"            "HOW SNORT
   settings &           actual work         FINDS US"
   definitions
```

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Snort3 Plugin Components                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐    │
│  │   IndpModule    │ ───── │      Indp       │ ───── │   InspectApi    │    │
│  │   (Module)      │       │   (Inspector)   │       │   (Plugin API)  │    │
│  ├─────────────────┤       ├─────────────────┤       ├─────────────────┤    │
│  │ • Parameters    │       │ • eval()        │       │ • IT_NETWORK    │    │
│  │ • Rules (SIDs)  │       │ • show()        │       │ • PROTO_BIT__IP │    │
│  │ • Peg counts    │       │ • Parsers       │       │ • Constructor   │    │
│  │ • set()/end()   │       │ • Caches        │       │ • Destructor    │    │
│  └─────────────────┘       └─────────────────┘       └─────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2. Configuration Flow

```
Snort Config (Lua)
       │
       ▼
┌─────────────────┐
│  IndpModule     │
│  set() called   │──── Parses: use_ipv6, flood_window, flood_count,
│  for each param │           topology_size, routers[], prefixes[]
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  IndpModule     │
│  end() called   │──── Validates prefix configurations
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  indp_ctor()    │──── Creates Indp(use_ipv6, flood_window, flood_count,
│                 │                  topology_size, routers, prefixes)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Indp::Indp()   │──── Initializes:
│  Constructor    │     • RouterCache (allowed routers)
│                 │     • HostCache (verified hosts)
│                 │     • TmpHostCache (pending verification)
│                 │     • Adds fe80::/64 to prefixes (link-local)
└─────────────────┘
```

### 3. Packet Processing Flow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         eval() Processing Flow                             │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  Packet arrives                                                            │
│       │                                                                    │
│       ▼                                                                    │
│  ┌─────────────┐     No                                                    │
│  │ is_ip6()?   │────────────► return (ignore)                              │
│  └──────┬──────┘                                                           │
│         │ Yes                                                              │
│         ▼                                                                  │
│  ┌─────────────┐     No      ┌────────────────────────────────────────────┐│
│  │ is_icmp()?  │────────────►│ parse_nonND()                              ││
│  └──────┬──────┘             │ Build topology from traffic                ││
│         │ Yes                │ Map of "who is who" on the network.        ││
│         ▼                    └────────────────────────────────────────────┘│
│  ┌─────────────────┐                                                       │
│  │  parse_icmp6()  │                                                       │
│  └────────┬────────┘                                                       │
│           │                                                                │
│           ▼                                                                │
│  ┌─────────────────┐                                                       │
│  │ Check type:     │                                                       │
│  │ 133-137 = NDP   │                                                       │
│  │ 130,143,151=MLD │                                                       │
│  └────────┬────────┘                                                       │
│           │                                                                │
│     ┌─────┴─────┬─────────┬─────────┬─────────┐                            │
│     ▼           ▼         ▼         ▼         ▼                            │
│  type=134    type=135  type=136  type=137   MLD                            │
│  parse_ra    parse_ns  parse_na  parse_     checks                         │
│  (Router     (Neighbor (Neighbor redirect                                  │
│   Advert)    Solicit)  Advert)                                             │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```


## Detection Logic Summary

### Router Advertisement Attacks (`parse_ra`)

> **Router Advertisement (RA) Attacks**:  
> An attacker sends fake or malicious Router Advertisement messages to disrupt IPv6 network routing. This can cause denial of service (by setting a very short router lifetime), introduce rogue routers (unauthorized devices that advertise themselves as routers to intercept or manipulate traffic), or change routing flags/prefixes to hijack or reroute traffic.

```
RA Packet Arrives
       │
       ▼
┌──────────────────┐
│ lifetime < 5?    │──── Yes ──► Alert: Router Kill (SID 3)
└────────┬─────────┘
         │ No
         ▼
┌──────────────────┐
│ MAC in allowed   │──── No ───► Alert: RA from non-Router (SID 4)
│ routers list?    │
└────────┬─────────┘
         │ Yes
         ▼
┌──────────────────┐
│ Router in cache? │──── No ───► Alert: New Router (SID 5)
└────────┬─────────┘             Add to cache
         │ Yes
         ▼
┌──────────────────┐
│ Flags changed?   │──── Yes ──► Alert: Router Flag Changed (SID 6)
└────────┬─────────┘
         │ No
         ▼
┌──────────────────┐
│ Prefix changed?  │──── Yes ──► Alert: Router Prefix Changed (SID 7)
└──────────────────┘
```

### Neighbor Cache Poisoning (`parse_na`)

> **Neighbor Cache Poisoning**:  
> The attacker sends spoofed Neighbor Advertisement (NA) messages to overwrite the mapping of an IPv6 address to a MAC address in the victim's cache. This can redirect traffic to the attacker (man-in-the-middle) or cause denial of service by breaking legitimate communication.

```
NA Packet Arrives
       │
       ▼
┌──────────────────┐
│ Target IP in     │──── No ───► Add to tmphosts (pending)
│ hosts cache?     │
└────────┬─────────┘
         │ Yes
         ▼
┌──────────────────┐
│ MAC changed for  │──── Yes ──► Alert: NC Poison (SID 15)
│ this IP?         │
└────────┬─────────┘
         │ No
         ▼
┌──────────────────┐
│ advertise_count  │──── Yes ──► Alert: Unsolicited Advertise (SID 12)
│ > 5?             │
└──────────────────┘
```

### DAD Attack Detection (`parse_ns`)

> **DAD (Duplicate Address Detection) Attacks**:  
> During IPv6 address assignment, hosts use Neighbor Solicitation (NS) to check if an address is already in use. An attacker can respond falsely, causing the victim to believe its address is taken (DoS), or can race to claim the address, leading to address conflicts or impersonation.

```
NS Packet Arrives (with src = ::)
       │
       ▼
       Alert: New DAD (SID 8)
       │
       ▼
┌──────────────────┐
│ Target in        │──── No ───► Add to tmphosts
│ tmphosts?        │
└────────┬─────────┘
         │ Yes
         ▼
┌──────────────────┐
│ Time since last  │──── No ───► Normal (update timestamp)
│ NS < 1 second?   │
└────────┬─────────┘
         │ Yes
         ▼
┌──────────────────┐
│ Same MAC as      │──── Yes ──► Alert: DAD Conflict (SID 10)
│ before?          │              (retransmission)
└────────┬─────────┘
         │ No
         ▼
         Alert: Spoofed DAD (SID 11)
         (Different host claiming same IP!)
```


## Key Differences from HTTP Inspector

| Aspect | NDP Inspector | HTTP Inspector |
|--------|---------------|----------------|
| **OSI Layer** | Layer 3 (Network) | Layer 7 (Application) |
| **Protocol** | ICMPv6 | HTTP over TCP |
| **Inspector Type** | `IT_NETWORK` | `IT_SERVICE` |
| **State Complexity** | Simple caches | FlowData + Transaction + Pipeline |
| **Stream Splitter** | Not needed | Required (HttpStreamSplitter) |
| **Packet Handling** | Single packet analysis | Multi-packet stream reassembly |
| **Code Size** | ~700 lines | ~50,000+ lines |
| **Configuration** | Router MACs, Prefixes | Depths, URI params, JS norm |

--- 

## IPS Option: Allows Snort rules to check whether a specific **IPv6 Extension Header** is present in a packet.


**Example rules:**
```
alert ip6 any any -> any any (ip6_exthdr:44; msg:"Fragment header present";)
alert ip6 any any -> any any (ip6_exthdr:!43; msg:"No routing header";)
```

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    IPS Option Plugin Architecture                          │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐     │
│  │  ExthdrModule   │ ──── │ IpExthdrOption  │ ──── │    IpsApi       │     │
│  │    (Module)     │      │  (IpsOption)    │      │  (Plugin API)   │     │
│  ├─────────────────┤      ├─────────────────┤      ├─────────────────┤     │
│  │ • Parameters    │      │ • eval()        │      │ • PT_IPS_OPTION │     │
│  │ • set()         │      │ • hash()        │      │ • Constructor   │     │
│  │ • begin()       │      │ • operator==    │      │ • Destructor    │     │
│  │ • Parsing       │      │ • config        │      │                 │     │
│  └─────────────────┘      └─────────────────┘      └─────────────────┘     │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. Configuration Structure

```cpp
enum class ExtOps : uint8_t 
{ 
    None = 1,    // Same as EQ (presence check)
    EQ = 1,      // Header must be present (=)
    NQ = 0       // Header must NOT be present (!)
};

struct ExtCheck 
{
    ProtocolId pId;  // Which extension header to look for
    ExtOps op;       // Presence or absence check
};
```

### 2. Supported Extension Headers

| Protocol ID | Constant | Description |
|-------------|----------|-------------|
| 0 | `HOPOPTS` | Hop-by-Hop Options |
| 43 | `ROUTING` | Routing Header |
| 44 | `FRAGMENT` | Fragment Header |
| 50 | `ESP` | Encapsulating Security Payload |
| 51 | `AUTH` | Authentication Header |
| 59 | `NONEXT` | No Next Header |
| 60 | `DSTOPTS` | Destination Options |
| 135 | `MOBILITY` | Mobility Header |

## Processing Flow

### Rule Parsing Flow

```
Rule: ip6_exthdr:!44
           │
           ▼
┌─────────────────────┐
│  ExthdrModule::set()│
│  Called with "!44"  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  exthdr_parse()     │
│  Parses the string  │
└──────────┬──────────┘
           │
           ▼
    ┌──────┴──────┐
    │ "!44"       │
    │  ↓          │
    │ op = NQ     │  (! means NOT present)
    │ pId = 44    │  → FRAGMENT
    └──────┬──────┘
           │
           ▼
┌─────────────────────┐
│  exthdr_ctor()      │
│  Creates IpsOption  │
│  with ExtCheck      │
└─────────────────────┘
```

### Packet Evaluation Flow (`eval()`)

```
Packet arrives
      │
      ▼
┌──────────────┐
│ is_ip6()?    │──── No ──► return NO_MATCH
└──────┬───────┘
       │ Yes
       ▼
┌──────────────────────────────────────────┐
│  Loop through packet layers              │
│                                          │
│  for (x = 0; x < num_layers; x++)        │
│  {                                       │
│      if (op == EQ)  // Looking FOR it    │
│      {                                   │
│          if (layers[x].prot_id == pId)   │
│              return MATCH;  ◄── Found!   │
│      }                                   │
│      else  // op == NQ, looking to avoid │
│      {                                   │
│          if (layers[x].prot_id == pId)   │
│              return NO_MATCH; ◄── Found! │
│      }                                   │
│  }                                       │
└──────────────────┬───────────────────────┘
                   │
                   ▼
         Loop finished without finding
                   │
      ┌────────────┴────────────┐
      │                         │
      ▼                         ▼
   op == EQ                  op == NQ
   (wanted it)               (didn't want it)
      │                         │
      ▼                         ▼
   NO_MATCH                   MATCH
   (not found)               (good, not there)
```
## Comparison: IPS Option vs Inspector

| Aspect | IPS Option (ip6_exthdr) | Inspector (indp) |
|--------|-------------------------|------------------|
| **Purpose** | Rule matching condition | Full packet analysis |
| **Plugin Type** | `PT_IPS_OPTION` | `PT_INSPECTOR` |
| **API Structure** | `IpsApi` | `InspectApi` |
| **Main Method** | `eval()` returns MATCH/NO_MATCH | `eval()` queues events |
| **State** | Stateless (per-rule config only) | Stateful (caches, tracking) |
| **Invocation** | Called when rule being evaluated | Called for every packet |
| **Output** | Contributes to rule match | Generates alerts directly |
| **Complexity** | ~200 lines | ~700+ lines |

## Usage in Snort Rules

```s
# Detect packets with Fragment header
alert ip6 any any -> any any (
    msg:"IPv6 Fragment Header Present";
    ip6_exthdr:44;
    sid:1000001;
)

# Detect packets WITHOUT Routing header (suspicious)
alert ip6 any any -> any any (
    msg:"IPv6 Missing Expected Routing Header";
    ip6_exthdr:!43;
    sid:1000002;
)

# Detect packets with Hop-by-Hop options
alert ip6 any any -> any any (
    msg:"IPv6 Hop-by-Hop Options Present";
    ip6_exthdr:0;
    sid:1000003;
)

# Combine with other options
alert ip6 any any -> any any (
    msg:"Fragmented packet to web server";
    ip6_exthdr:44;
    dst_port:80;
    sid:1000004;
)
```

## Key Takeaways

1. **Simpler than Inspectors** - IPS options are stateless rule conditions
2. **Three main components:**
   - `Module` - Parses configuration from rules
   - `IpsOption` - Runtime evaluation logic
   - `IpsApi` - Plugin registration
3. **eval() returns:**
   - `MATCH` - Condition satisfied
   - `NO_MATCH` - Condition not satisfied
4. **Packet layer iteration** - Uses `p->layers[]` to check protocol stack
5. **Operator support** - `=` (present), `!` (not present), or default (present)
