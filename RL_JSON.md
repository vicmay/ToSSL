# `rl_json`: Native JSON Handling for Tcl

## Introduction

The `rl_json` package provides efficient and robust JSON manipulation capabilities for Tcl. Unlike simple string-based approaches, `rl_json` introduces a **native JSON data type** within Tcl (`Tcl_Obj` type). This allows for:

*   **Type Safety:** JSON structures (objects, arrays, strings, numbers, booleans, nulls) retain their distinct types.
*   **Performance:** Operations directly manipulate the internal representation, similar to how Tcl's `dict` command works efficiently with dictionaries.
*   **Rich API:** Offers a comprehensive set of commands for creating, querying, modifying, and iterating over JSON data.

## Getting Started

To use the package, load it into your Tcl script:

```tcl
package require rl_json
```

## Core Concept: Native JSON Values

When you parse a JSON string using `rl_json::json decode` or construct JSON using commands like `rl_json::json object`, the result is a special Tcl value that internally represents the JSON structure. Many `rl_json` commands operate directly on these native values.

## Creating JSON Values

You can build JSON values programmatically.

### Primitive Values

Use these commands to create basic JSON types directly:

*   **`rl_json::json string <value>`**: Creates a JSON string.
    ```tcl
    set jsonStr [rl_json::json string "Hello, world!"]
    # jsonStr now represents "Hello, world!"
    ```
*   **`rl_json::json number <value>`**: Creates a JSON number.
    ```tcl
    set jsonNum [rl_json::json number 123.45]
    # jsonNum now represents 123.45
    ```
*   **`rl_json::json boolean <value>`**: Creates a JSON boolean. Accepts Tcl boolean forms (1, 0, true, false, yes, no, etc.) and normalizes them.
    ```tcl
    set jsonBool [rl_json::json boolean true]
    # jsonBool now represents true
    ```
*   **JSON Null**: The documentation implies `null` is a type used in `{type value}` pairs (see below), but doesn't list a specific `rl_json::json null` command. To represent JSON null, you typically use the `{null null}` pair or rely on default behaviors (like non-existent keys in templates).

### JSON Objects

*   **`rl_json::json object ?key value ?key value ...??`**
*   **`rl_json::json object <packed_value>`** (Alternate syntax with a single list argument)

    Creates a JSON object. The crucial point is the format of each `value` argument:

    **Each `value` must be a two-element Tcl list: `{type data}`**

    Where `type` is one of:
    *   `string`: The `data` is treated as a string.
    *   `number`: The `data` is treated as a number.
    *   `boolean`: The `data` is treated as a boolean (and normalized).
    *   `null`: Represents a JSON null (the `data` part is often ignored, often use `{null null}`).
    *   `object`: The `data` should be another valid JSON object value (e.g., created by `rl_json::json object`).
    *   `array`: The `data` should be another valid JSON array value (e.g., created by `rl_json::json array`).
    *   `json`: The `data` is an existing native JSON value (e.g., from `rl_json::json extract` or `rl_json::json decode`).

    **Example:**
    ```tcl
    set name "Alice"
    set age 30
    set city "New York"
    set preferences [rl_json::json object theme {string dark} notifications {boolean true}]

    set user [rl_json::json object \
        name    {string $name} \
        age     {number $age} \
        city    {string $city} \
        active  {boolean true} \
        profile {null null} \
        prefs   {object $preferences}  ;# Nesting an existing object
    ]

    # user now represents:
    # {"name":"Alice","age":30,"city":"New York","active":true,"profile":null,"prefs":{"theme":"dark","notifications":true}}
    ```

### JSON Arrays

*   **`rl_json::json array ?element ...?`**

    Creates a JSON array. Like `rl_json::json object`, each `element` argument must be a two-element Tcl list specifying the type and data:

    **Each `element` must be a two-element Tcl list: `{type data}`**

    The `type` keywords are the same as for `rl_json::json object`.

    **Example:**
    ```tcl
    set item1 "Apple"
    set item2 5
    set item3 [rl_json::json boolean false]

    set jsonArr [rl_json::json array \
        {string $item1} \
        {number $item2} \
        {boolean $item3}    ;# Use the pre-created boolean value
        {string "Orange"} \
        {null null}
    ]

    # jsonArr now represents: ["Apple",5,false,"Orange",null]
    ```

## Reading and Querying JSON

These commands inspect existing JSON values.

*   **`rl_json::json get ?-default <defaultValue>? <jsonValue> ?key ...?`**
    *   Extracts the value at the specified path.
    *   Returns the value converted to the **closest native Tcl type** (string, integer, double, boolean as 1/0). JSON objects/arrays become Tcl dicts/lists.
    *   Use `-default` to provide a fallback if the path doesn't exist.
    ```tcl
    set user {{"name":"Bob","age":25,"roles":["user","editor"]}}
    set name [rl_json::json get $user name] ;# Returns string "Bob"
    set age [rl_json::json get $user age]   ;# Returns integer 25
    set roles [rl_json::json get $user roles] ;# Returns Tcl list {user editor}
    set city [rl_json::json get -default "N/A" $user city] ;# Returns string "N/A"
    ```

*   **`rl_json::json extract ?-default <defaultValue>? <jsonValue> ?key ...?`**
    *   Extracts the value at the specified path.
    *   Returns the value as a **native JSON fragment**, preserving its JSON type.
    ```tcl
    set user {{"name":"Bob","age":25,"roles":["user","editor"]}}
    set rolesJson [rl_json::json extract $user roles] ;# rolesJson is a native JSON array value
    puts [rl_json::json type $rolesJson] ;# Output: array
    ```

*   **`rl_json::json exists <jsonValue> ?key ...?`**
    *   Checks if the path exists within the JSON value **and** the value at that path is not JSON `null`.
    *   Returns `true` (1) or `false` (0).
    ```tcl
    set data {{"status":"active","details":null,"count":0}}
    puts [rl_json::json exists $data status]   ;# Output: 1 (true)
    puts [rl_json::json exists $data details]  ;# Output: 0 (false, because value is null)
    puts [rl_json::json exists $data count]    ;# Output: 1 (true, 0 is not null)
    puts [rl_json::json exists $data missing]  ;# Output: 0 (false)
    ```

*   **`rl_json::json type <jsonValue> ?key ...?`**
    *   Returns the JSON type of the value at the path as a string: `object`, `array`, `string`, `number`, `boolean`, or `null`.
    ```tcl
    set data {{"a":1,"b":"txt","c":true,"d":null,"e":[],"f":{}}}
    puts [rl_json::json type $data a] ;# Output: number
    puts [rl_json::json type $data b] ;# Output: string
    puts [rl_json::json type $data c] ;# Output: boolean
    puts [rl_json::json type $data d] ;# Output: null
    puts [rl_json::json type $data e] ;# Output: array
    puts [rl_json::json type $data f] ;# Output: object
    ```

*   **`rl_json::json length <jsonValue> ?key ...?`**
    *   Returns the number of elements in an array, key-value pairs in an object, or characters in a string.
    *   Throws an error for other types (number, boolean, null).
    ```tcl
    set data {{"arr":[1,2,3],"obj":{"x":1,"y":2},"str":"hello"}}
    puts [rl_json::json length $data arr] ;# Output: 3
    puts [rl_json::json length $data obj] ;# Output: 2
    puts [rl_json::json length $data str] ;# Output: 5
    ```

*   **`rl_json::json keys <jsonValue> ?key ...?`**
    *   Returns a Tcl list of the keys within the JSON object at the specified path.
    *   Throws an error if the target is not an object.
    ```tcl
    set data {{"user":{"name":"Alice","age":30}}}
    puts [rl_json::json keys $data user] ;# Output: name age (order not guaranteed)
    ```

*   **`rl_json::json isnull <jsonValue> ?key ...?`**
    *   Checks if the value at the specified path is specifically JSON `null`.
    *   Returns `true` (1) or `false` (0).
    ```tcl
    set data {{"status":"active","details":null,"count":0}}
    puts [rl_json::json isnull $data status]   ;# Output: 0 (false)
    puts [rl_json::json isnull $data details]  ;# Output: 1 (true)
    puts [rl_json::json isnull $data count]    ;# Output: 0 (false)
    puts [rl_json::json isnull $data missing]  ;# Output: 0 (false, path doesn't exist)
    ```

## Modifying JSON

These commands modify JSON values stored in Tcl variables.

*   **`rl_json::json set <jsonVariableName> ?key ...? <value>`**
    *   Updates the JSON value stored in the variable `<jsonVariableName>`.
    *   Replaces or creates the value at the specified path with the given `<value>`.
    *   The `<value>` should be a native JSON value (e.g., created using `rl_json::json string`, `object`, `array`, etc., or extracted using `rl_json::json extract`). You can also use plain Tcl strings, numbers, or booleans, and `rl_json` will generally convert them appropriately.
    *   If intermediate keys in the path don't exist, they are created as nested objects.
    *   If an array index is out of bounds, nulls are added to pad the array.
    ```tcl
    set data [rl_json::json object name {string Alice}]
    # Set age (creates key)
    rl_json::json set data age [rl_json::json number 31]
    # Set nested value (creates objects)
    rl_json::json set data address city {string London}
    # Set array element (creates array and pads)
    rl_json::json set data roles 0 {string admin}
    # data is now {"name":"Alice","age":31,"address":{"city":"London"},"roles":["admin"]}
    ```

*   **`rl_json::json unset <jsonVariableName> ?key ...?`**
    *   Removes the key (for objects) or element (for arrays) at the specified path from the JSON value stored in `<jsonVariableName>`.
    *   Does nothing if the path doesn't exist.
    ```tcl
    set data {{"name":"Alice","age":31,"address":{"city":"London"},"roles":["admin","user"]}}
    rl_json::json unset data age
    rl_json::json unset data address city
    rl_json::json unset data roles 1
    # data is now {"name":"Alice","address":{},"roles":["admin"]}
    ```

## Working with Paths

Commands like `get`, `extract`, `set`, `unset`, and `exists` use paths to specify parts of the JSON structure.

*   **Object Keys:** Use the key name directly (e.g., `user`, `address`, `city`).
*   **Array Indices:** Use zero-based integer indices (e.g., `0`, `1`, `2`).
*   **Special Array Indices:** You can use `end` or `end-<offset>` to index relative to the end of an array.
    *   `end`: The last element.
    *   `end-1`: The second-to-last element.
    *   `end+1` (used with `json set`): Appends an element.
*   **Nested Paths:** Combine keys and indices (e.g., `user roles 0`, `foo end-1 name`).

## Iteration

These commands iterate over JSON objects or arrays.

*   **`rl_json::json foreach <varlist1> <json_val1> ?<varlist2> <json_val2> ...? <script>`**
    *   Similar to Tcl's `foreach`.
    *   Iterates over elements of arrays or key-value pairs of objects.
    *   For objects, `<varlist>` must have two variables (key, value).
    *   For arrays, `<varlist>` works like standard `foreach`.
    *   The loop variables receive **native JSON fragments**. Use `rl_json::json get` if you need the Tcl representation.
    ```tcl
    set data {{"a":1,"b":2}}
    rl_json::json foreach {k v} $data {
        puts "Key: $k, Value (JSON): $v, Value (Tcl): [rl_json::json get $v]"
    }
    # Output:
    # Key: a, Value (JSON): 1, Value (Tcl): 1
    # Key: b, Value (JSON): 2, Value (Tcl): 2

    set arr {[10,"x",true]}
    rl_json::json foreach elem $arr {
        puts "Element (JSON): $elem, Type: [rl_json::json type $elem]"
    }
    # Output:
    # Element (JSON): 10, Type: number
    # Element (JSON): "x", Type: string
    # Element (JSON): true, Type: boolean
    ```

*   **`rl_json::json lmap ... <script>`**: Like `foreach`, but collects results of `<script>` into a Tcl list.
*   **`rl_json::json amap ... <script>`**: Like `lmap`, but collects results into a JSON array.
*   **`rl_json::json omap ... <script>`**: Like `lmap`, but collects results into a JSON object (script must return dicts or key-value lists).

## Templates (`rl_json::json template`)

*   **`rl_json::json template <jsonTemplateValue> ?<dictionary>?`**

    A powerful way to generate JSON by substituting values into a template string. The template itself must be valid JSON.

    **Substitution Syntax:** Placeholders within JSON *string* values in the template:
    *   `~S:<name>`: Substitute as JSON String. `<name>` is key in dict or variable name.
    *   `~N:<name>`: Substitute as JSON Number.
    *   `~B:<name>`: Substitute as JSON Boolean.
    *   `~J:<name>`: Substitute as JSON Fragment (value must be valid JSON).
    *   `~T:<name>`: Substitute as JSON Template (value is treated as another template and substituted recursively).
    *   `~L:<text>`: Literal text. Everything after `~L:` is included verbatim (use this if your data starts with `~S:` etc.).

    If `<dictionary>` is provided, `<name>` refers to keys in that dictionary.
    If `<dictionary>` is omitted, `<name>` refers to variables in the current Tcl scope.
    If a `<name>` doesn't exist, JSON `null` is substituted.

    **Example:**
    ```tcl
    set template { # This is a Tcl string containing valid JSON
        {
            "user": "~S:username",
            "id":   "~N:user_id",
            "active": "~B:is_active",
            "metadata": "~J:user_meta",
            "description": "~L:User object ~S:username"
        }
    }

    set user_data [dict create \
        username  "charlie" \
        user_id   987 \
        is_active true \
        user_meta {[{"role":"guest"}]} ] ;# user_meta value is already JSON

    set result [rl_json::json template $template $user_data]

    # result represents:
    # {"user":"charlie","id":987,"active":true,"metadata":[{"role":"guest"}],"description":"User object ~S:username"}
    ```

## Utility Commands

*   **`rl_json::json pretty ?-indent <indentString>? <jsonValue> ?key ...?`**
    *   Returns a formatted string representation of the JSON value with indentation (default is 4 spaces).
    ```tcl
    set data {{"a":1,"b":[2,3]}}
    puts [rl_json::json pretty $data] ;
    # Output:
    # {
    #     "a": 1,
    #     "b": [
    #         2,
    #         3
    #     ]
    # }
    ```

*   **`rl_json::json normalize <jsonValue>`**
    *   Returns a compact string representation with no optional whitespace.
    ```tcl
    set data [rl_json::json pretty {{"a": 1}}]
    puts [rl_json::json normalize $data] ;# Output: {"a":1}
    ```

*   **`rl_json::json valid ?options? <jsonValue>`**
    *   Checks if the input string conforms to JSON grammar. Returns `true` (1) or `false` (0).
    *   Options:
        *   `-extensions <list>`: Specify extensions (only `comments` supported, enabled by default). Use `{}` to disallow comments.
        *   `-details <varName>`: If invalid, store details (error message, offset) in the named variable.
    ```tcl
    puts [rl_json::json valid {{"key": "value"}}] ;# Output: 1
    puts [rl_json::json valid {{"key": "value",}}] ;# Output: 0 (trailing comma)
    if {![rl_json::json valid -details errInfo {{"key": "value",}}] } {
        puts "Invalid: $errInfo"
        # Output: Invalid: errmsg {Unexpected token } doc {{"key": "value",}} char_ofs 16
    }
    ```

*   **`rl_json::json decode <bytes> ?<encoding>?`**
    *   Decodes a string of *bytes* (e.g., read from a file in binary mode) into a Tcl character string, handling JSON-specified encodings and BOMs.
    *   Use this when reading JSON data from external sources to ensure correct character interpretation.
    *   Encodings: `utf-8` (default), `utf-16le`, `utf-16be`, `utf-32le`, `utf-32be`.
    ```tcl
    # Example: Reading a UTF-8 file
    set fh [open "data.json" r] ; # Open in text mode, Tcl handles basic encoding
    fconfigure $fh -encoding utf-8
    set jsonString [read $fh]
    close $fh
    set jsonData [rl_json::json decode $jsonString] ;# Decode handles JSON escapes

    # Example: Reading potentially unknown encoding (more robust)
    set fh [open "data.json" rb] ; # Open in binary mode
    set fileBytes [read $fh]
    close $fh
    set jsonData [rl_json::json decode $fileBytes] ;# Decode handles BOM and encoding
    ```

## Deprecated Commands (Version 0.10.0)

The following commands are deprecated and will be removed in future versions. Use the suggested replacements:

*   `json get_type ...` -> Use `json get` and `json type` separately.
*   `json parse ...` -> Use `json get ...` (or `rl_json::json decode` if starting from bytes).
*   `json fmt ...` -> Use `json new ...`.
*   `json new <type> <value>` -> Use specific constructors: `json string`, `json number`, `json boolean`, `json object`, `json array`.
*   Path modifiers (`?type`, `?length`, `?keys`) -> Use specific commands: `json type`, `json length`, `json keys`. 