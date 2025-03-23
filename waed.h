// waed.h
// A zero-dependency C23 library for WebAssembly module manipulation

#ifndef WAED_H
#define WAED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Error codes
typedef enum
{
    WAED_SUCCESS = 0,
    WAED_ERROR_INVALID_ARGUMENT,
    WAED_ERROR_MEMORY_ALLOCATION,
    WAED_ERROR_IO,
    WAED_ERROR_INVALID_FORMAT,
    WAED_ERROR_INVALID_SECTION,
    WAED_ERROR_UNSUPPORTED_VERSION
} waed_error_t;

// WebAssembly section IDs
typedef enum
{
    WAED_SECTION_CUSTOM = 0,
    WAED_SECTION_TYPE = 1,
    WAED_SECTION_IMPORT = 2,
    WAED_SECTION_FUNCTION = 3,
    WAED_SECTION_TABLE = 4,
    WAED_SECTION_MEMORY = 5,
    WAED_SECTION_GLOBAL = 6,
    WAED_SECTION_EXPORT = 7,
    WAED_SECTION_START = 8,
    WAED_SECTION_ELEMENT = 9,
    WAED_SECTION_CODE = 10,
    WAED_SECTION_DATA = 11,
    // Recent additions to the spec
    WAED_SECTION_DATA_COUNT = 12
} waed_section_id_t;

// WebAssembly value types
typedef enum
{
    WAED_TYPE_I32 = 0x7F,
    WAED_TYPE_I64 = 0x7E,
    WAED_TYPE_F32 = 0x7D,
    WAED_TYPE_F64 = 0x7C,
    WAED_TYPE_V128 = 0x7B, // SIMD extension
    WAED_TYPE_FUNCREF = 0x70,
    WAED_TYPE_EXTERNREF = 0x6F
} waed_value_type_t;

// Import/Export kinds
typedef enum
{
    WAED_KIND_FUNCTION = 0,
    WAED_KIND_TABLE = 1,
    WAED_KIND_MEMORY = 2,
    WAED_KIND_GLOBAL = 3
} waed_external_kind_t;

// Forward declarations for opaque types
typedef struct waed_module waed_module_t;
typedef struct waed_custom_section waed_custom_section_t;
typedef struct waed_function_type waed_function_type_t;
typedef struct waed_import waed_import_t;
typedef struct waed_export waed_export_t;

// Function type representation
struct waed_function_type
{
    uint32_t param_count;
    waed_value_type_t *param_types;
    uint32_t result_count;
    waed_value_type_t *result_types;
};

// Import entry representation
struct waed_import
{
    char *module_name;
    char *field_name;
    waed_external_kind_t kind;
    uint32_t type_index; // For function imports
};

// Export entry representation
struct waed_export
{
    char *name;
    waed_external_kind_t kind;
    uint32_t index;
};

// Custom section representation
struct waed_custom_section
{
    char *name;
    uint8_t *content;
    size_t content_size;
};

// Create a new empty WebAssembly module
waed_module_t *waed_module_create(void);

// Load a WebAssembly module from a file
waed_error_t waed_module_load_file(const char *path, waed_module_t **out_module);

// Load a WebAssembly module from memory
waed_error_t waed_module_load_buffer(const uint8_t *buffer, size_t size, waed_module_t **out_module);

// Write a WebAssembly module to a file
waed_error_t waed_module_save_file(const waed_module_t *module, const char *path);

// Serialize a WebAssembly module to a memory buffer (caller must free with waed_free_buffer)
waed_error_t waed_module_serialize(const waed_module_t *module, uint8_t **out_buffer, size_t *out_size);

// Free a buffer allocated by the library
void waed_free_buffer(uint8_t *buffer);

// Free a WebAssembly module and all associated resources
void waed_module_destroy(waed_module_t *module);

// Get the number of custom sections in a module
uint32_t waed_module_get_custom_section_count(const waed_module_t *module);

// Get a custom section by index
waed_error_t waed_module_get_custom_section(const waed_module_t *module,
                                            uint32_t index,
                                            waed_custom_section_t *out_section);

// Find a custom section by name (returns NULL if not found)
waed_error_t waed_module_find_custom_section(const waed_module_t *module,
                                             const char *name,
                                             waed_custom_section_t *out_section);

// Add a custom section to a module
waed_error_t waed_module_add_custom_section(waed_module_t *module,
                                            const char *name,
                                            const uint8_t *content,
                                            size_t content_size);

// Remove a custom section from a module by name
waed_error_t waed_module_remove_custom_section(waed_module_t *module, const char *name);

// Get the number of function types in a module
uint32_t waed_module_get_type_count(const waed_module_t *module);

// Get a function type by index
waed_error_t waed_module_get_type(const waed_module_t *module,
                                  uint32_t index,
                                  waed_function_type_t *out_type);

// Get the number of imports in a module
uint32_t waed_module_get_import_count(const waed_module_t *module);

// Get an import by index
waed_error_t waed_module_get_import(const waed_module_t *module,
                                    uint32_t index,
                                    waed_import_t *out_import);

// Get the number of exports in a module
uint32_t waed_module_get_export_count(const waed_module_t *module);

// Get an export by index
waed_error_t waed_module_get_export(const waed_module_t *module,
                                    uint32_t index,
                                    waed_export_t *out_export);

// Find an export by name (returns WAED_ERROR_INVALID_SECTION if not found)
waed_error_t waed_module_find_export(const waed_module_t *module,
                                     const char *name,
                                     waed_export_t *out_export);

// Get the function type of an export (only valid for function exports)
waed_error_t waed_module_get_export_function_type(const waed_module_t *module,
                                                  const waed_export_t *export_,
                                                  waed_function_type_t *out_type);

// Get the function type of an import (only valid for function imports)
waed_error_t waed_module_get_import_function_type(const waed_module_t *module,
                                                  const waed_import_t *import_,
                                                  waed_function_type_t *out_type);

// Get the last error message
const char *waed_get_error_message(void);

#endif // WAED_H