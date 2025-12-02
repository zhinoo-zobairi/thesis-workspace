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


## HOW SNORT PLUGINS WORK

 ┌─────────────────────────────────────────────────────────────────────────┐
 │                           SNORT 'CORE'                                    │
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

 ## MODULE vs INSPECTOR: THE TWO PIECES

 ┌──────────────────────┬────────────────────────────────────────────────┐
 │ Component            │ What it does                                   │
 ├──────────────────────┼────────────────────────────────────────────────┤
 │ Module (HttpModule)  │ Reads config, validates values, stores settings│
 │ 
 │Inspector            │ Does the actual work (inspects packets)        │
 │ (HttpInspect)        │                                                │
 └──────────────────────┴────────────────────────────────────────────────┘

 STARTUP SEQUENCE:
 -----------------

 Phase 1: CONFIG PARSING
 ┌──────────────────────────────────────────────────────────────────────┐
 │ 1. Snort core reads snort.lua                                        │
 │ 2. Sees "http_inspect = { decompress_pdf = true, ... }"              │
 │ 3. Snort calls: HttpApi::http_mod_ctor()                            │
 │                 ↓                                                     │
 │ 4. Creates: HttpModule object                                        │
 │ 5. Snort hands config data to HttpModule                            │
 │ 6. HttpModule validates and stores settings                         │
 └──────────────────────────────────────────────────────────────────────┘

 At this point:
   - HttpModule exists (config parser)
   - HttpInspect does NOT exist yet (no packet processor)


 Phase 2: PACKET PROCESSING (runtime)
 ┌──────────────────────────────────────────────────────────────────────┐
 │ 7. First HTTP packet arrives                                         │
 │ 8. Snort calls: HttpApi::http_ctor(module)                          │
 │                                     ^^^^^^                            │
 │                                     Passes the HttpModule            │
 │                 ↓                                                     │
 │ 9. Creates: HttpInspect object                                       │
 │ 10. HttpInspect reads settings FROM the HttpModule                  │
 │ 11. HttpInspect processes the packet                                │
 └──────────────────────────────────────────────────────────────────────┘

 Now:
   HttpModule exists (config parser)
   HttpInspect exists (packet processor)



## How Snort Finds sin_http[] and Other Plugin Arrays

If Snort uses `sin_http[]` as the starting point to discover the HTTP inspector plugin, how does Snort find this script/array in the first place?

## Two Methods (Static vs Dynamic)

Snort plugins can be:
1. **Built-in (static)** - compiled directly into the Snort executable
2. **Dynamic (.so)** - loaded at runtime as shared libraries

## Method 1: Built-In Plugins (Static Linking)

### Step 1: CMake creates object libraries

In `src/service_inspectors/http_inspect/CMakeLists.txt`:
```cmake
add_library(http_inspect OBJECT ${FILE_LIST})
```

This compiles all HTTP inspector files, including `http_api.cc` (which contains `sin_http[]`), into object files.

### Step 2: Object files are linked into Snort executable

In `src/service_inspectors/CMakeLists.txt`:
```cmake
set(STATIC_SERVICE_INSPECTOR_PLUGINS
    $<TARGET_OBJECTS:http_inspect>
    $<TARGET_OBJECTS:http2_inspect>
    $<TARGET_OBJECTS:dns>
    ...
)
```

This tells CMake: "Take these object files and link them into the main Snort executable."

When the linker runs, it includes all the code from `http_api.cc`, making `sin_http[]` a **global symbol** in the final executable.

### Step 3: Snort startup code explicitly references sin_http[]

Somewhere in Snort's initialization code (in `src/managers/plugin_manager.cc` or similar), there's code like:

```cpp
// These are extern declarations - they reference the arrays from each plugin
extern const BaseApi* sin_http[];
extern const BaseApi* sin_dns[];
extern const BaseApi* sin_ftp[];
// ... all other built-in plugins ...

void load_builtin_plugins() {
    register_plugin_list(sin_http);
    register_plugin_list(sin_dns);
    register_plugin_list(sin_ftp);
    // ... etc
}
```

This code:
- **Declares** `extern const BaseApi* sin_http[]` - says "this array exists somewhere"
- The linker **resolves** it to the actual `sin_http[]` defined in `http_api.cc`
- Calls a function to register all plugins in the array

**Important:** This code is either:
- Hand-written in the plugin manager
- Auto-generated by CMake during the build process

### Step 4: At Snort startup

```
Snort main() starts
    ↓
Calls PluginManager::load_plugins()
    ↓
load_builtin_plugins() is called
    ↓
Loops through sin_http[], sin_dns[], etc.
    ↓
Registers each plugin with Snort core
```

## Method 2: Dynamic Plugins (Shared Libraries .so)

### Step 1: Build as shared library

In `http_inspect/CMakeLists.txt` (if building dynamically):
```cmake
add_dynamic_module(http_inspect inspectors ${FILE_LIST})
```

This creates `libhttp_inspect.so` containing the HTTP inspector code.

### Step 2: Config file specifies .so to load

In your `snort.lua` configuration file:
```lua
plugins = {
    { library = "/usr/local/lib/snort/libhttp_inspect.so" }
}
```

### Step 3: Snort uses dlopen() to load the library

In `src/managers/plugin_manager.cc` line 257:
```cpp
static bool load_lib(const char* file, SnortConfig* sc)
{
    // Open the shared library
    void* handle = dlopen(file, RTLD_NOW|RTLD_LOCAL);
    if (!handle) {
        // Error handling...
        return false;
    }
    
    // Look for the "snort_plugins" symbol
    const BaseApi** api = (const BaseApi**)dlsym(handle, "snort_plugins");
    
    if (!api) {
        // Error handling...
        dlclose(handle);
        return false;
    }
    
    // Register all plugins in the array
    load_list(api, handle, file, sc);
    return true;
}
```

**Key functions:**
- `dlopen()` - Opens the .so file and loads it into memory
- `dlsym()` - Looks up a symbol by name ("snort_plugins")
- Returns a pointer to the `snort_plugins[]` array

### Step 4: Different array name for .so files

Notice in `http_api.cc`:
```cpp
#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =  // For .so files
#else
const BaseApi* sin_http[] =                  // For built-in
#endif
{
    &HttpApi::http_api.base,
    ips_http_client_body,
    // ... etc
};
```

**Why two names?**
- **Built-in:** Each plugin has unique name (`sin_http`, `sin_dns`, `sin_ftp`) so they don't clash when linked together
- **Dynamic:** All `.so` files use the same name (`snort_plugins`) because each is in its own file, loaded separately

## Visual Comparison

### Built-In (Static) Flow:
```
┌──────────────────────────────────────────────────────────────┐
│ CMake Build Time                                             │
├──────────────────────────────────────────────────────────────┤
│ 1. Compile http_api.cc → object file (contains sin_http[])  │
│ 2. Link object files into snort executable                  │
│ 3. sin_http[] becomes global symbol in executable           │
└──────────────────────────────────────────────────────────────┘
                           ↓
┌──────────────────────────────────────────────────────────────┐
│ Snort Startup                                                │
├──────────────────────────────────────────────────────────────┤
│ 1. main() starts                                             │
│ 2. Call load_builtin_plugins()                              │
│ 3. Code says: extern const BaseApi* sin_http[];             │
│ 4. Linker resolves to actual sin_http[] from http_api.cc    │
│ 5. Loop through array and register plugins                  │
└──────────────────────────────────────────────────────────────┘
```

### Dynamic (.so) Flow:
```
┌──────────────────────────────────────────────────────────────┐
│ CMake Build Time                                             │
├──────────────────────────────────────────────────────────────┤
│ 1. Compile http_api.cc                                       │
│ 2. Link into libhttp_inspect.so                             │
│ 3. Export snort_plugins[] as public symbol                  │
└──────────────────────────────────────────────────────────────┘
                           ↓
┌──────────────────────────────────────────────────────────────┐
│ Snort Startup                                                │
├──────────────────────────────────────────────────────────────┤
│ 1. Read snort.lua config                                     │
│ 2. See: plugins = { { library = "libhttp_inspect.so" } }    │
│ 3. Call dlopen("libhttp_inspect.so")                        │
│ 4. Call dlsym(handle, "snort_plugins")                      │
│ 5. Get pointer to snort_plugins[] array                     │
│ 6. Loop through array and register plugins                  │
└──────────────────────────────────────────────────────────────┘
```

## Key Insight

**The discovery mechanism is different:**

| Method | Discovery | When |
|--------|-----------|------|
| **Static (built-in)** | Snort code explicitly references `sin_http[]` via `extern` | Compile time |
| **Dynamic (.so)** | Snort searches for symbol `"snort_plugins"` via `dlsym()` | Runtime |


## Analogy

### Built-In Plugins:
Like a restaurant where the chef (Snort) has a fixed list of dishes (plugins) memorized in their recipe book. The recipes are compiled into the book, and the chef just flips to the page for "HTTP Inspector" when needed.

### Dynamic Plugins:
Like a restaurant where the chef (Snort) reads the menu (config file) to see what additional cookbooks (`.so` files) to fetch from the shelf. Each cookbook has a table of contents page called "snort_plugins" that the chef looks for.

## For Your MQTT Plugin

When you create an MQTT plugin, you'll need:

**If built-in:**
```cpp
const BaseApi* sin_mqtt[] = {
    &MqttApi::mqtt_api.base,
    ips_mqtt_topic,
    ips_mqtt_payload,
    nullptr
};
```

And somewhere in Snort's plugin manager:
```cpp
extern const BaseApi* sin_mqtt[];
register_plugin_list(sin_mqtt);
```

**If dynamic:**
```cpp
#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] = {
#else
const BaseApi* sin_mqtt[] = {
#endif
    &MqttApi::mqtt_api.base,
    ips_mqtt_topic,
    ips_mqtt_payload,
    nullptr
};
```
