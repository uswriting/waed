# waed (WebAssembly Embedded Data)

waed is a zero-dependency C library and CLI tool for parsing and manipulating WebAssembly modules. It specializes in working with WebAssembly custom sections, making it easy to embed, extract, and manage arbitrary data within WebAssembly modules.

## Installation

### Download Release

Download the latest release from the [GitHub releases page](https://github.com/uswriting/waed/releases).

### Building from Source

```bash
git clone https://github.com/uswriting/waed.git
cd waed
make
sudo make install
```

## CLI Usage

```
Usage: waed [OPTIONS] COMMAND WASM_FILE

Commands:
  list                   List all custom sections in the WebAssembly module
  add                    Add a custom section from a file
  get                    Extract a custom section to a file or stdout

Options:
  -h, --help             Display this help message and exit
  -v, --version          Display version information and exit
  -x[N], --hex[=N]       Display section content as hex dump (max N bytes, default 32)
  -n, --name=NAME        Set custom section name (required for 'get', optional for 'add')
  -f, --file=FILE        Input file for 'add' command
  -o, --output=FILE      Output file for 'add' and 'get' commands
```

### Examples

List all custom sections in a WebAssembly module:

```bash
waed list example.wasm
```

Add a custom section with data from a file:

```bash
waed add -n "metadata" -f metadata.json -o output.wasm example.wasm 
```

Extract a custom section to a file:

```bash
waed get -n "metadata" -o metadata.json example.wasm 
```

Display a custom section as a hex dump:

```bash
waed get -n "metadata" -x example.wasm 
```

## Library Example

```c
#include "waed.h"
#include <stdio.h>

int main() {
    waed_module_t *module;
    waed_error_t result = waed_module_load_file("example.wasm", &module);
    
    if (result != waed_SUCCESS) {
        fprintf(stderr, "Error: %s\n", waed_get_error_message());
        return 1;
    }
    
    // List all custom sections
    uint32_t custom_count = waed_module_get_custom_section_count(module);
    printf("Found %u custom sections\n", custom_count);
    
    for (uint32_t i = 0; i < custom_count; i++) {
        waed_custom_section_t section;
        result = waed_module_get_custom_section(module, i, &section);
        
        if (result == waed_SUCCESS) {
            printf("Section %u: %s (%zu bytes)\n", i, section.name, section.content_size);
        }
    }
    
    // Clean up
    waed_module_destroy(module);
    return 0;
}
```

## License

waed is licensed under the MIT License. See the LICENSE file for details.