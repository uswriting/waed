#include "waed.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Error message storage
#ifdef __STDC_NO_THREADS__
static char error_message[256]; // Fallback for systems without thread support
#else
static thread_local char error_message[256];
#endif

// Forward declarations for internal functions
static waed_error_t parse_module(waed_module_t *module, const uint8_t *buffer, size_t size);
static waed_error_t serialize_module(const waed_module_t *module, uint8_t **out_buffer, size_t *out_size);

// WASM binary format constants
#define WASM_MAGIC 0x6D736100 // "\0asm"
#define WASM_VERSION 0x01     // Current supported version
#define WAED_MAX_NAME_LENGTH 256

// Section implementation structure
typedef struct
{
    waed_section_id_t id;
    size_t size;
    size_t offset; // Offset in the original buffer
    uint8_t *data; // Section data (excluding ID and size)
} section_t;

// Custom section implementation
typedef struct
{
    char *name;
    uint8_t *content;
    size_t content_size;
} custom_section_impl_t;

// Module implementation structure
struct waed_module
{
    uint8_t *buffer;    // Original buffer (if loaded from memory or file)
    size_t buffer_size; // Size of the original buffer

    // Parsed sections
    section_t *sections; // All sections in order
    size_t section_count;

    // Custom sections (for easier access)
    custom_section_impl_t *custom_sections;
    size_t custom_section_count;

    // Type section data
    waed_function_type_t *types;
    size_t type_count;

    // Import section data
    waed_import_t *imports;
    size_t import_count;

    // Function section data
    uint32_t *function_type_indices;
    size_t function_count;

    // Export section data
    waed_export_t *exports;
    size_t export_count;
};

// LEB128 variable-length encoding utilities
static size_t read_unsigned_leb128(const uint8_t *buffer, size_t max, uint32_t *out)
{
    uint32_t result = 0;
    size_t shift = 0;
    size_t offset = 0;
    uint8_t byte;

    do
    {
        if (offset >= max)
        {
            snprintf(error_message, sizeof(error_message),
                     "Invalid LEB128 encoding: unexpected end of buffer");
            return 0;
        }

        byte = buffer[offset++];
        result |= ((uint32_t)(byte & 0x7F)) << shift;
        shift += 7;

        // Protect against malicious inputs causing integer overflow
        if (shift > 32)
        {
            snprintf(error_message, sizeof(error_message),
                     "Invalid LEB128 encoding: value exceeds 32 bits");
            return 0;
        }
    } while (byte & 0x80);

    *out = result;
    return offset;
}

static size_t read_signed_leb128(const uint8_t *buffer, size_t max, int32_t *out)
{
    uint32_t result = 0;
    size_t shift = 0;
    size_t offset = 0;
    uint8_t byte;

    do
    {
        if (offset >= max)
        {
            snprintf(error_message, sizeof(error_message),
                     "Invalid LEB128 encoding: unexpected end of buffer");
            return 0;
        }

        byte = buffer[offset++];
        result |= ((uint32_t)(byte & 0x7F)) << shift;
        shift += 7;

        // Protect against malicious inputs causing integer overflow
        if (shift > 32)
        {
            snprintf(error_message, sizeof(error_message),
                     "Invalid LEB128 encoding: value exceeds 32 bits");
            return 0;
        }
    } while (byte & 0x80);

    // Sign extend if the last byte has the sign bit set
    if (shift < 32 && (byte & 0x40))
    {
        result |= (~0U << shift);
    }

    *out = (int32_t)result;
    return offset;
}

static size_t write_unsigned_leb128(uint8_t *buffer, uint32_t value)
{
    size_t offset = 0;
    do
    {
        uint8_t byte = value & 0x7F;
        value >>= 7;
        if (value != 0)
        {
            byte |= 0x80; // More bytes to follow
        }
        buffer[offset++] = byte;
    } while (value != 0);

    return offset;
}

static size_t write_signed_leb128(uint8_t *buffer, int32_t value)
{
    size_t offset = 0;
    bool more = true;

    while (more)
    {
        uint8_t byte = value & 0x7F;
        value >>= 7;

        // Sign bit of byte is second high order bit (0x40)
        if ((value == 0 && !(byte & 0x40)) ||
            (value == -1 && (byte & 0x40)))
        {
            more = false;
        }
        else
        {
            byte |= 0x80; // More bytes to follow
        }

        buffer[offset++] = byte;
    }

    return offset;
}

static size_t get_unsigned_leb128_size(uint32_t value)
{
    size_t size = 0;
    do
    {
        value >>= 7;
        size++;
    } while (value != 0);
    return size;
}

// String reading/writing helpers
static size_t read_string(const uint8_t *buffer, size_t max, char **out_str)
{
    uint32_t length;
    size_t offset = read_unsigned_leb128(buffer, max, &length);
    if (offset == 0)
        return 0;

    if (offset + length > max)
    {
        snprintf(error_message, sizeof(error_message),
                 "Invalid string: length exceeds buffer bounds");
        return 0;
    }

    *out_str = malloc(length + 1);
    if (*out_str == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Memory allocation failed");
        return 0;
    }

    memcpy(*out_str, buffer + offset, length);
    (*out_str)[length] = '\0';

    return offset + length;
}

static size_t write_string(uint8_t *buffer, const char *str)
{
    size_t length = strlen(str);
    size_t offset = write_unsigned_leb128(buffer, (uint32_t)length);

    memcpy(buffer + offset, str, length);
    return offset + length;
}

static size_t get_string_size(const char *str)
{
    size_t length = strlen(str);
    return get_unsigned_leb128_size((uint32_t)length) + length;
}

// Parsing implementation
static waed_error_t parse_module(waed_module_t *module, const uint8_t *buffer, size_t size)
{
    // Check minimum size for header
    if (size < 8)
    {
        snprintf(error_message, sizeof(error_message),
                 "Invalid WASM module: file too small");
        return WAED_ERROR_INVALID_FORMAT;
    }

    // Check magic number
    uint32_t magic = (buffer[0] << 0) | (buffer[1] << 8) |
                     (buffer[2] << 16) | (buffer[3] << 24);
    if (magic != WASM_MAGIC)
    {
        snprintf(error_message, sizeof(error_message),
                 "Invalid WASM module: incorrect magic number");
        return WAED_ERROR_INVALID_FORMAT;
    }

    // Check version
    uint32_t version = (buffer[4] << 0) | (buffer[5] << 8) |
                       (buffer[6] << 16) | (buffer[7] << 24);
    if (version != WASM_VERSION)
    {
        snprintf(error_message, sizeof(error_message),
                 "Unsupported WASM version: %u", version);
        return WAED_ERROR_UNSUPPORTED_VERSION;
    }

    // First pass: count sections
    size_t pos = 8; // Skip header
    size_t section_count = 0;

    while (pos < size)
    {
        if (pos + 1 > size)
        {
            snprintf(error_message, sizeof(error_message),
                     "Invalid WASM module: unexpected end of file");
            return WAED_ERROR_INVALID_FORMAT;
        }

        // Read section ID
        uint8_t id = buffer[pos++];

        // Read section size
        uint32_t section_size;
        size_t leb_size = read_unsigned_leb128(buffer + pos, size - pos, &section_size);
        if (leb_size == 0)
            return WAED_ERROR_INVALID_FORMAT;
        pos += leb_size;

        // Check if section extends beyond the buffer
        if (pos + section_size > size)
        {
            snprintf(error_message, sizeof(error_message),
                     "Invalid WASM module: section extends beyond file boundaries");
            return WAED_ERROR_INVALID_FORMAT;
        }

        section_count++;
        pos += section_size; // Skip to next section
    }

    // Allocate sections array
    module->sections = calloc(section_count, sizeof(section_t));
    if (module->sections == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Memory allocation failed");
        return WAED_ERROR_MEMORY_ALLOCATION;
    }

    // Second pass: store section data
    pos = 8; // Reset to start of sections
    size_t custom_section_count = 0;

    for (size_t i = 0; i < section_count; i++)
    {
        uint8_t id = buffer[pos++];

        uint32_t section_size;
        size_t leb_size = read_unsigned_leb128(buffer + pos, size - pos, &section_size);
        pos += leb_size;

        module->sections[i].id = (waed_section_id_t)id;
        module->sections[i].size = section_size;
        module->sections[i].offset = pos;

        // For custom sections, count them
        if (id == WAED_SECTION_CUSTOM)
        {
            custom_section_count++;
        }

        pos += section_size; // Move to next section
    }

    module->section_count = section_count;

    // Allocate custom sections array
    if (custom_section_count > 0)
    {
        module->custom_sections = calloc(custom_section_count, sizeof(custom_section_impl_t));
        if (module->custom_sections == NULL)
        {
            snprintf(error_message, sizeof(error_message), "Memory allocation failed");
            return WAED_ERROR_MEMORY_ALLOCATION;
        }
    }

    // Parse sections
    size_t custom_index = 0;

    for (size_t i = 0; i < section_count; i++)
    {
        section_t *section = &module->sections[i];
        const uint8_t *section_data = buffer + section->offset;

        if (section->id == WAED_SECTION_CUSTOM)
        {
            char *name;
            size_t name_offset = read_string(section_data, section->size, &name);
            if (name_offset == 0)
            {
                return WAED_ERROR_INVALID_FORMAT;
            }

            size_t content_size = section->size - name_offset;
            uint8_t *content = malloc(content_size);
            if (content == NULL)
            {
                free(name);
                snprintf(error_message, sizeof(error_message), "Memory allocation failed");
                return WAED_ERROR_MEMORY_ALLOCATION;
            }

            memcpy(content, section_data + name_offset, content_size);

            custom_section_impl_t *custom = &module->custom_sections[custom_index++];
            custom->name = name;
            custom->content = content;
            custom->content_size = content_size;
        }
        else if (section->id == WAED_SECTION_TYPE)
        {
            // Parse type section
            uint32_t count;
            size_t offset = read_unsigned_leb128(section_data, section->size, &count);
            if (offset == 0)
                return WAED_ERROR_INVALID_FORMAT;

            module->types = calloc(count, sizeof(waed_function_type_t));
            if (module->types == NULL)
            {
                snprintf(error_message, sizeof(error_message), "Memory allocation failed");
                return WAED_ERROR_MEMORY_ALLOCATION;
            }

            module->type_count = count;

            for (uint32_t j = 0; j < count; j++)
            {
                // According to the WebAssembly spec, the function type form is a single byte 0x60
                // not a LEB128 value. Read it directly.
                if (offset >= section->size)
                {
                    snprintf(error_message, sizeof(error_message),
                             "Invalid format: unexpected end of section");
                    return WAED_ERROR_INVALID_FORMAT;
                }

                uint8_t form_byte = section_data[offset++];

                // Be lenient about the form type - print a warning but continue
                if (form_byte != 0x60)
                {
                    printf("Warning: Unexpected function type form: 0x%02x (expected 0x60)\n", form_byte);
                }

                // Read parameter count
                uint32_t param_count;
                size_t param_count_size = read_unsigned_leb128(section_data + offset,
                                                               section->size - offset,
                                                               &param_count);
                if (param_count_size == 0)
                    return WAED_ERROR_INVALID_FORMAT;
                offset += param_count_size;

                // Allocate parameter types array
                waed_value_type_t *param_types = NULL;
                if (param_count > 0)
                {
                    param_types = calloc(param_count, sizeof(waed_value_type_t));
                    if (param_types == NULL)
                    {
                        snprintf(error_message, sizeof(error_message), "Memory allocation failed");
                        return WAED_ERROR_MEMORY_ALLOCATION;
                    }
                }

                // Read parameter types
                for (uint32_t k = 0; k < param_count; k++)
                {
                    // Value types are single bytes in WebAssembly, not LEB128
                    if (offset >= section->size)
                    {
                        free(param_types);
                        snprintf(error_message, sizeof(error_message),
                                 "Invalid format: unexpected end of section");
                        return WAED_ERROR_INVALID_FORMAT;
                    }

                    int8_t value_type = (int8_t)section_data[offset++];
                    param_types[k] = (waed_value_type_t)value_type;
                }

                // Read result count
                uint32_t result_count;
                size_t result_count_size = read_unsigned_leb128(section_data + offset,
                                                                section->size - offset,
                                                                &result_count);
                if (result_count_size == 0)
                {
                    free(param_types);
                    return WAED_ERROR_INVALID_FORMAT;
                }
                offset += result_count_size;

                // Allocate result types array
                waed_value_type_t *result_types = NULL;
                if (result_count > 0)
                {
                    result_types = calloc(result_count, sizeof(waed_value_type_t));
                    if (result_types == NULL)
                    {
                        free(param_types);
                        snprintf(error_message, sizeof(error_message), "Memory allocation failed");
                        return WAED_ERROR_MEMORY_ALLOCATION;
                    }
                }

                // Read result types
                for (uint32_t k = 0; k < result_count; k++)
                {
                    // Value types are single bytes in WebAssembly, not LEB128
                    if (offset >= section->size)
                    {
                        free(param_types);
                        free(result_types);
                        snprintf(error_message, sizeof(error_message),
                                 "Invalid format: unexpected end of section");
                        return WAED_ERROR_INVALID_FORMAT;
                    }

                    int8_t value_type = (int8_t)section_data[offset++];
                    result_types[k] = (waed_value_type_t)value_type;
                }

                // Store the function type
                module->types[j].param_count = param_count;
                module->types[j].param_types = param_types;
                module->types[j].result_count = result_count;
                module->types[j].result_types = result_types;
            }
        }
        else if (section->id == WAED_SECTION_IMPORT)
        {
            // Parse import section
            uint32_t count;
            size_t offset = read_unsigned_leb128(section_data, section->size, &count);
            if (offset == 0)
                return WAED_ERROR_INVALID_FORMAT;

            module->imports = calloc(count, sizeof(waed_import_t));
            if (module->imports == NULL)
            {
                snprintf(error_message, sizeof(error_message), "Memory allocation failed");
                return WAED_ERROR_MEMORY_ALLOCATION;
            }

            module->import_count = count;

            for (uint32_t j = 0; j < count; j++)
            {
                // Read module name
                char *module_name;
                size_t module_name_size = read_string(section_data + offset,
                                                      section->size - offset,
                                                      &module_name);
                if (module_name_size == 0)
                    return WAED_ERROR_INVALID_FORMAT;
                offset += module_name_size;

                // Read field name
                char *field_name;
                size_t field_name_size = read_string(section_data + offset,
                                                     section->size - offset,
                                                     &field_name);
                if (field_name_size == 0)
                {
                    free(module_name);
                    return WAED_ERROR_INVALID_FORMAT;
                }
                offset += field_name_size;

                // Read kind
                uint32_t kind;
                size_t kind_size = read_unsigned_leb128(section_data + offset,
                                                        section->size - offset, &kind);
                if (kind_size == 0)
                {
                    free(module_name);
                    free(field_name);
                    return WAED_ERROR_INVALID_FORMAT;
                }
                offset += kind_size;

                uint32_t type_index = 0;

                // Read type index for function imports
                if (kind == WAED_KIND_FUNCTION)
                {
                    size_t type_index_size = read_unsigned_leb128(section_data + offset,
                                                                  section->size - offset,
                                                                  &type_index);
                    if (type_index_size == 0)
                    {
                        free(module_name);
                        free(field_name);
                        return WAED_ERROR_INVALID_FORMAT;
                    }
                    offset += type_index_size;
                }
                else
                {
                    // Handle other import types (table, memory, global)
                    if (kind == WAED_KIND_TABLE)
                    {
                        // Skip table element type (1 byte)
                        if (offset >= section->size)
                        {
                            free(module_name);
                            free(field_name);
                            return WAED_ERROR_INVALID_FORMAT;
                        }
                        offset++; // Skip element type

                        // Skip table limits
                        if (offset >= section->size)
                        {
                            free(module_name);
                            free(field_name);
                            return WAED_ERROR_INVALID_FORMAT;
                        }

                        uint8_t has_max = section_data[offset++];

                        // Read min value
                        uint32_t min_size;
                        size_t min_size_len = read_unsigned_leb128(section_data + offset,
                                                                   section->size - offset,
                                                                   &min_size);
                        if (min_size_len == 0)
                        {
                            free(module_name);
                            free(field_name);
                            return WAED_ERROR_INVALID_FORMAT;
                        }
                        offset += min_size_len;

                        // Read max value if present
                        if (has_max)
                        {
                            uint32_t max_size;
                            size_t max_size_len = read_unsigned_leb128(section_data + offset,
                                                                       section->size - offset,
                                                                       &max_size);
                            if (max_size_len == 0)
                            {
                                free(module_name);
                                free(field_name);
                                return WAED_ERROR_INVALID_FORMAT;
                            }
                            offset += max_size_len;
                        }
                    }
                    else if (kind == WAED_KIND_MEMORY)
                    {
                        // Skip memory limits
                        if (offset >= section->size)
                        {
                            free(module_name);
                            free(field_name);
                            return WAED_ERROR_INVALID_FORMAT;
                        }

                        uint8_t has_max = section_data[offset++];

                        // Read min value
                        uint32_t min_size;
                        size_t min_size_len = read_unsigned_leb128(section_data + offset,
                                                                   section->size - offset,
                                                                   &min_size);
                        if (min_size_len == 0)
                        {
                            free(module_name);
                            free(field_name);
                            return WAED_ERROR_INVALID_FORMAT;
                        }
                        offset += min_size_len;

                        // Read max value if present
                        if (has_max)
                        {
                            uint32_t max_size;
                            size_t max_size_len = read_unsigned_leb128(section_data + offset,
                                                                       section->size - offset,
                                                                       &max_size);
                            if (max_size_len == 0)
                            {
                                free(module_name);
                                free(field_name);
                                return WAED_ERROR_INVALID_FORMAT;
                            }
                            offset += max_size_len;
                        }
                    }
                    else if (kind == WAED_KIND_GLOBAL)
                    {
                        // Skip value type (1 byte)
                        if (offset >= section->size)
                        {
                            free(module_name);
                            free(field_name);
                            return WAED_ERROR_INVALID_FORMAT;
                        }
                        offset++; // Value type

                        // Skip mutability (1 byte)
                        if (offset >= section->size)
                        {
                            free(module_name);
                            free(field_name);
                            return WAED_ERROR_INVALID_FORMAT;
                        }
                        offset++; // Mutability
                    }
                }

                // Store the import
                module->imports[j].module_name = module_name;
                module->imports[j].field_name = field_name;
                module->imports[j].kind = (waed_external_kind_t)kind;
                module->imports[j].type_index = type_index;
            }
        }
        else if (section->id == WAED_SECTION_FUNCTION)
        {
            // Parse function section
            uint32_t count;
            size_t offset = read_unsigned_leb128(section_data, section->size, &count);
            if (offset == 0)
                return WAED_ERROR_INVALID_FORMAT;

            module->function_type_indices = calloc(count, sizeof(uint32_t));
            if (module->function_type_indices == NULL)
            {
                snprintf(error_message, sizeof(error_message), "Memory allocation failed");
                return WAED_ERROR_MEMORY_ALLOCATION;
            }

            module->function_count = count;

            for (uint32_t j = 0; j < count; j++)
            {
                uint32_t type_index;
                size_t type_index_size = read_unsigned_leb128(section_data + offset,
                                                              section->size - offset,
                                                              &type_index);
                if (type_index_size == 0)
                    return WAED_ERROR_INVALID_FORMAT;
                offset += type_index_size;

                module->function_type_indices[j] = type_index;
            }
        }
        else if (section->id == WAED_SECTION_EXPORT)
        {
            // Parse export section
            uint32_t count;
            size_t offset = read_unsigned_leb128(section_data, section->size, &count);
            if (offset == 0)
                return WAED_ERROR_INVALID_FORMAT;

            module->exports = calloc(count, sizeof(waed_export_t));
            if (module->exports == NULL)
            {
                snprintf(error_message, sizeof(error_message), "Memory allocation failed");
                return WAED_ERROR_MEMORY_ALLOCATION;
            }

            module->export_count = count;

            for (uint32_t j = 0; j < count; j++)
            {
                // Read export name
                char *name;
                size_t name_size = read_string(section_data + offset,
                                               section->size - offset, &name);
                if (name_size == 0)
                    return WAED_ERROR_INVALID_FORMAT;
                offset += name_size;

                // Read kind
                uint32_t kind;
                size_t kind_size = read_unsigned_leb128(section_data + offset,
                                                        section->size - offset, &kind);
                if (kind_size == 0)
                {
                    free(name);
                    return WAED_ERROR_INVALID_FORMAT;
                }
                offset += kind_size;

                // Read index
                uint32_t index;
                size_t index_size = read_unsigned_leb128(section_data + offset,
                                                         section->size - offset, &index);
                if (index_size == 0)
                {
                    free(name);
                    return WAED_ERROR_INVALID_FORMAT;
                }
                offset += index_size;

                // Store the export
                module->exports[j].name = name;
                module->exports[j].kind = (waed_external_kind_t)kind;
                module->exports[j].index = index;
            }
        }
        // Other section types are not fully parsed in this simplified implementation
    }

    module->custom_section_count = custom_section_count;
    return WAED_SUCCESS;
}

// Serialize module to a memory buffer
static waed_error_t serialize_module(const waed_module_t *module, uint8_t **out_buffer, size_t *out_size)
{
    // First pass: calculate the size of the serialized module
    size_t total_size = 8; // 4 bytes magic + 4 bytes version

    // If the module has the original buffer and no custom sections were added/removed
    // we can just return a copy of the original buffer
    if (module->buffer != NULL &&
        module->sections != NULL &&
        module->custom_section_count == 0)
    {
        uint8_t *buffer_copy = malloc(module->buffer_size);
        if (buffer_copy == NULL)
        {
            snprintf(error_message, sizeof(error_message), "Memory allocation failed");
            return WAED_ERROR_MEMORY_ALLOCATION;
        }

        memcpy(buffer_copy, module->buffer, module->buffer_size);
        *out_buffer = buffer_copy;
        *out_size = module->buffer_size;

        return WAED_SUCCESS;
    }

    // Add size for original non-custom sections
    for (size_t i = 0; i < module->section_count; i++)
    {
        if (module->sections[i].id != WAED_SECTION_CUSTOM)
        {
            // 1 byte for the section ID
            // LEB128 bytes for the section size
            // The section data itself
            total_size += 1 + get_unsigned_leb128_size((uint32_t)module->sections[i].size) + module->sections[i].size;
        }
    }

    // Add size for custom sections
    for (size_t i = 0; i < module->custom_section_count; i++)
    {
        custom_section_impl_t *section = &module->custom_sections[i];

        // 1 byte for the section ID
        // Size of the section name (LEB128 length + string)
        // Section content
        size_t name_size = get_string_size(section->name);
        size_t section_size = name_size + section->content_size;

        total_size += 1 + get_unsigned_leb128_size((uint32_t)section_size) + section_size;
    }

    // Allocate buffer for the serialized module
    uint8_t *buffer = malloc(total_size);
    if (buffer == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Memory allocation failed");
        return WAED_ERROR_MEMORY_ALLOCATION;
    }

    // Write magic number and version
    buffer[0] = 0x00; // \0
    buffer[1] = 0x61; // a
    buffer[2] = 0x73; // s
    buffer[3] = 0x6D; // m
    buffer[4] = 0x01; // version 1
    buffer[5] = 0x00;
    buffer[6] = 0x00;
    buffer[7] = 0x00;

    size_t offset = 8;

    // Write original non-custom sections
    for (size_t i = 0; i < module->section_count; i++)
    {
        if (module->sections[i].id != WAED_SECTION_CUSTOM)
        {
            section_t *section = &module->sections[i];

            // Write section ID
            buffer[offset++] = (uint8_t)section->id;

            // Write section size
            offset += write_unsigned_leb128(buffer + offset, (uint32_t)section->size);

            // Write section data
            memcpy(buffer + offset, module->buffer + section->offset, section->size);
            offset += section->size;
        }
    }

    // Write custom sections
    for (size_t i = 0; i < module->custom_section_count; i++)
    {
        custom_section_impl_t *section = &module->custom_sections[i];

        // Calculate section size
        size_t name_size = get_string_size(section->name);
        size_t section_size = name_size + section->content_size;

        // Write section ID
        buffer[offset++] = (uint8_t)WAED_SECTION_CUSTOM;

        // Write section size
        offset += write_unsigned_leb128(buffer + offset, (uint32_t)section_size);

        // Write section name
        offset += write_string(buffer + offset, section->name);

        // Write section content
        memcpy(buffer + offset, section->content, section->content_size);
        offset += section->content_size;
    }

    *out_buffer = buffer;
    *out_size = total_size;

    return WAED_SUCCESS;
}

// Public API implementations

// Create a new empty WebAssembly module
waed_module_t *waed_module_create(void)
{
    waed_module_t *module = calloc(1, sizeof(waed_module_t));
    return module;
}

// Load a WebAssembly module from a file
waed_error_t waed_module_load_file(const char *path, waed_module_t **out_module)
{
    if (path == NULL || out_module == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    FILE *file = fopen(path, "rb");
    if (file == NULL)
    {
        snprintf(error_message, sizeof(error_message),
                 "Failed to open file: %s", path);
        return WAED_ERROR_IO;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0)
    {
        fclose(file);
        snprintf(error_message, sizeof(error_message),
                 "Invalid file size: %ld", file_size);
        return WAED_ERROR_IO;
    }

    // Allocate memory for the file content
    uint8_t *buffer = malloc(file_size);
    if (buffer == NULL)
    {
        fclose(file);
        snprintf(error_message, sizeof(error_message), "Memory allocation failed");
        return WAED_ERROR_MEMORY_ALLOCATION;
    }

    // Read the file content
    size_t bytes_read = fread(buffer, 1, file_size, file);
    fclose(file);

    if (bytes_read != file_size)
    {
        free(buffer);
        snprintf(error_message, sizeof(error_message),
                 "Failed to read file: expected %ld bytes, got %zu",
                 file_size, bytes_read);
        return WAED_ERROR_IO;
    }

    // Create and initialize the module
    waed_module_t *module = calloc(1, sizeof(waed_module_t));
    if (module == NULL)
    {
        free(buffer);
        snprintf(error_message, sizeof(error_message), "Memory allocation failed");
        return WAED_ERROR_MEMORY_ALLOCATION;
    }

    module->buffer = buffer;
    module->buffer_size = file_size;

    // Parse the module
    waed_error_t result = parse_module(module, buffer, file_size);
    if (result != WAED_SUCCESS)
    {
        waed_module_destroy(module);
        return result;
    }

    *out_module = module;
    return WAED_SUCCESS;
}

// Load a WebAssembly module from memory
waed_error_t waed_module_load_buffer(const uint8_t *buffer, size_t size, waed_module_t **out_module)
{
    if (buffer == NULL || out_module == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    if (size < 8)
    { // Minimum size for a valid WASM module (magic + version)
        snprintf(error_message, sizeof(error_message),
                 "Invalid buffer size: %zu", size);
        return WAED_ERROR_INVALID_FORMAT;
    }

    // Create and initialize the module
    waed_module_t *module = calloc(1, sizeof(waed_module_t));
    if (module == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Memory allocation failed");
        return WAED_ERROR_MEMORY_ALLOCATION;
    }

    // Make a copy of the buffer
    uint8_t *buffer_copy = malloc(size);
    if (buffer_copy == NULL)
    {
        free(module);
        snprintf(error_message, sizeof(error_message), "Memory allocation failed");
        return WAED_ERROR_MEMORY_ALLOCATION;
    }

    memcpy(buffer_copy, buffer, size);
    module->buffer = buffer_copy;
    module->buffer_size = size;

    // Parse the module
    waed_error_t result = parse_module(module, buffer_copy, size);
    if (result != WAED_SUCCESS)
    {
        waed_module_destroy(module);
        return result;
    }

    *out_module = module;
    return WAED_SUCCESS;
}

// Write a WebAssembly module to a file
waed_error_t waed_module_save_file(const waed_module_t *module, const char *path)
{
    if (module == NULL || path == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    // Serialize module to memory first
    uint8_t *buffer;
    size_t size;
    waed_error_t result = waed_module_serialize(module, &buffer, &size);
    if (result != WAED_SUCCESS)
    {
        return result;
    }

    // Open the file for writing
    FILE *file = fopen(path, "wb");
    if (file == NULL)
    {
        free(buffer);
        snprintf(error_message, sizeof(error_message), "Failed to open file for writing");
        return WAED_ERROR_IO;
    }

    // Write the serialized module to the file
    size_t bytes_written = fwrite(buffer, 1, size, file);
    fclose(file);
    free(buffer);

    if (bytes_written != size)
    {
        snprintf(error_message, sizeof(error_message),
                 "Failed to write file: expected %zu bytes, wrote %zu",
                 size, bytes_written);
        return WAED_ERROR_IO;
    }

    return WAED_SUCCESS;
}

// Serialize a WebAssembly module to a memory buffer (caller must free with waed_free_buffer)
waed_error_t waed_module_serialize(const waed_module_t *module, uint8_t **out_buffer, size_t *out_size)
{
    if (module == NULL || out_buffer == NULL || out_size == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    return serialize_module(module, out_buffer, out_size);
}

// Free a buffer allocated by the library
void waed_free_buffer(uint8_t *buffer)
{
    free(buffer);
}

// Free a WebAssembly module and all associated resources
void waed_module_destroy(waed_module_t *module)
{
    if (module == NULL)
    {
        return;
    }

    // Free custom sections
    for (size_t i = 0; i < module->custom_section_count; i++)
    {
        free(module->custom_sections[i].name);
        free(module->custom_sections[i].content);
    }
    free(module->custom_sections);

    // Free function types
    for (size_t i = 0; i < module->type_count; i++)
    {
        free(module->types[i].param_types);
        free(module->types[i].result_types);
    }
    free(module->types);

    // Free imports
    for (size_t i = 0; i < module->import_count; i++)
    {
        free(module->imports[i].module_name);
        free(module->imports[i].field_name);
    }
    free(module->imports);

    // Free exports
    for (size_t i = 0; i < module->export_count; i++)
    {
        free(module->exports[i].name);
    }
    free(module->exports);

    // Free function type indices
    free(module->function_type_indices);

    // Free sections
    free(module->sections);

    // Free buffer
    free(module->buffer);

    // Free module
    free(module);
}

// Get the number of custom sections in a module
uint32_t waed_module_get_custom_section_count(const waed_module_t *module)
{
    if (module == NULL)
    {
        return 0;
    }
    return (uint32_t)module->custom_section_count;
}

// Get a custom section by index
waed_error_t waed_module_get_custom_section(const waed_module_t *module,
                                            uint32_t index,
                                            waed_custom_section_t *out_section)
{
    if (module == NULL || out_section == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    if (index >= module->custom_section_count)
    {
        snprintf(error_message, sizeof(error_message),
                 "Invalid custom section index: %u", index);
        return WAED_ERROR_INVALID_SECTION;
    }

    custom_section_impl_t *custom = &module->custom_sections[index];
    out_section->name = custom->name;
    out_section->content = custom->content;
    out_section->content_size = custom->content_size;

    return WAED_SUCCESS;
}

// Find a custom section by name
waed_error_t waed_module_find_custom_section(const waed_module_t *module,
                                             const char *name,
                                             waed_custom_section_t *out_section)
{
    if (module == NULL || name == NULL || out_section == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    for (size_t i = 0; i < module->custom_section_count; i++)
    {
        if (strncmp(module->custom_sections[i].name, name, WAED_MAX_NAME_LENGTH) == 0)
        {
            out_section->name = module->custom_sections[i].name;
            out_section->content = module->custom_sections[i].content;
            out_section->content_size = module->custom_sections[i].content_size;
            return WAED_SUCCESS;
        }
    }

    snprintf(error_message, sizeof(error_message),
             "Custom section not found: %s", name);
    return WAED_ERROR_INVALID_SECTION;
}

// Add a custom section to a module
waed_error_t waed_module_add_custom_section(waed_module_t *module,
                                            const char *name,
                                            const uint8_t *content,
                                            size_t content_size)
{
    if (module == NULL || name == NULL || (content == NULL && content_size > 0))
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    // First check if a section with this name already exists
    for (size_t i = 0; i < module->custom_section_count; i++)
    {
        if (module->custom_sections[i].name != NULL &&
            strcmp(module->custom_sections[i].name, name) == 0)
        {
            snprintf(error_message, sizeof(error_message),
                     "Custom section '%s' already exists", name);
            return WAED_ERROR_DUPLICATE_SECTION;
        }
    }

    // Grow the custom sections array
    size_t new_count = module->custom_section_count + 1;
    custom_section_impl_t *new_sections = realloc(module->custom_sections,
                                                  new_count * sizeof(custom_section_impl_t));
    if (new_sections == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Memory allocation failed");
        return WAED_ERROR_MEMORY_ALLOCATION;
    }

    module->custom_sections = new_sections;

    // Create the new custom section
    custom_section_impl_t *new_section = &module->custom_sections[module->custom_section_count];

    // Copy the name
    new_section->name = strdup(name);
    if (new_section->name == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Memory allocation failed");
        return WAED_ERROR_MEMORY_ALLOCATION;
    }

    // Copy the content
    if (content_size > 0)
    {
        new_section->content = malloc(content_size);
        if (new_section->content == NULL)
        {
            free(new_section->name);
            snprintf(error_message, sizeof(error_message), "Memory allocation failed");
            return WAED_ERROR_MEMORY_ALLOCATION;
        }
        memcpy(new_section->content, content, content_size);
    }
    else
    {
        new_section->content = NULL;
    }

    new_section->content_size = content_size;
    module->custom_section_count = new_count;

    return WAED_SUCCESS;
}

// Remove a custom section from a module by name
waed_error_t waed_module_remove_custom_section(waed_module_t *module, const char *name)
{
    if (module == NULL || name == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    size_t index = SIZE_MAX;
    for (size_t i = 0; i < module->custom_section_count; i++)
    {
        if (strncmp(module->custom_sections[i].name, name, WAED_MAX_NAME_LENGTH) == 0)
        {
            index = i;
            break;
        }
    }

    if (index == SIZE_MAX)
    {
        snprintf(error_message, sizeof(error_message),
                 "Custom section not found: %s", name);
        return WAED_ERROR_INVALID_SECTION;
    }

    // Free the custom section resources
    free(module->custom_sections[index].name);
    free(module->custom_sections[index].content);

    // Shift all sections after this one
    for (size_t i = index; i < module->custom_section_count - 1; i++)
    {
        module->custom_sections[i] = module->custom_sections[i + 1];
    }

    // Reduce the count
    module->custom_section_count--;

    // Resize the array if we're not empty
    if (module->custom_section_count > 0)
    {
        custom_section_impl_t *new_sections = realloc(module->custom_sections,
                                                      module->custom_section_count * sizeof(custom_section_impl_t));
        if (new_sections != NULL)
        {
            module->custom_sections = new_sections;
        }
        // Even if realloc fails, the memory is still valid, just not optimally sized
    }
    else
    {
        // If no sections left, free the array
        free(module->custom_sections);
        module->custom_sections = NULL;
    }

    return WAED_SUCCESS;
}

// Get the number of function types in a module
uint32_t waed_module_get_type_count(const waed_module_t *module)
{
    if (module == NULL)
    {
        return 0;
    }
    return (uint32_t)module->type_count;
}

// Get a function type by index
waed_error_t waed_module_get_type(const waed_module_t *module,
                                  uint32_t index,
                                  waed_function_type_t *out_type)
{
    if (module == NULL || out_type == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    if (index >= module->type_count)
    {
        snprintf(error_message, sizeof(error_message),
                 "Invalid type index: %u", index);
        return WAED_ERROR_INVALID_SECTION;
    }

    out_type->param_count = module->types[index].param_count;
    out_type->param_types = module->types[index].param_types;
    out_type->result_count = module->types[index].result_count;
    out_type->result_types = module->types[index].result_types;

    return WAED_SUCCESS;
}

// Get the number of imports in a module
uint32_t waed_module_get_import_count(const waed_module_t *module)
{
    if (module == NULL)
    {
        return 0;
    }
    return (uint32_t)module->import_count;
}

// Get an import by index
waed_error_t waed_module_get_import(const waed_module_t *module,
                                    uint32_t index,
                                    waed_import_t *out_import)
{
    if (module == NULL || out_import == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    if (index >= module->import_count)
    {
        snprintf(error_message, sizeof(error_message),
                 "Invalid import index: %u", index);
        return WAED_ERROR_INVALID_SECTION;
    }

    out_import->module_name = module->imports[index].module_name;
    out_import->field_name = module->imports[index].field_name;
    out_import->kind = module->imports[index].kind;
    out_import->type_index = module->imports[index].type_index;

    return WAED_SUCCESS;
}

// Get the number of exports in a module
uint32_t waed_module_get_export_count(const waed_module_t *module)
{
    if (module == NULL)
    {
        return 0;
    }
    return (uint32_t)module->export_count;
}

// Get an export by index
waed_error_t waed_module_get_export(const waed_module_t *module,
                                    uint32_t index,
                                    waed_export_t *out_export)
{
    if (module == NULL || out_export == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    if (index >= module->export_count)
    {
        snprintf(error_message, sizeof(error_message),
                 "Invalid export index: %u", index);
        return WAED_ERROR_INVALID_SECTION;
    }

    out_export->name = module->exports[index].name;
    out_export->kind = module->exports[index].kind;
    out_export->index = module->exports[index].index;

    return WAED_SUCCESS;
}

// Find an export by name
waed_error_t waed_module_find_export(const waed_module_t *module,
                                     const char *name,
                                     waed_export_t *out_export)
{
    if (module == NULL || name == NULL || out_export == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    for (size_t i = 0; i < module->export_count; i++)
    {
        if (strncmp(module->exports[i].name, name, WAED_MAX_NAME_LENGTH) == 0)
        {
            out_export->name = module->exports[i].name;
            out_export->kind = module->exports[i].kind;
            out_export->index = module->exports[i].index;
            return WAED_SUCCESS;
        }
    }

    snprintf(error_message, sizeof(error_message),
             "Export not found: %s", name);
    return WAED_ERROR_INVALID_SECTION;
}

// Get the function type of an export
waed_error_t waed_module_get_export_function_type(const waed_module_t *module,
                                                  const waed_export_t *export_,
                                                  waed_function_type_t *out_type)
{
    if (module == NULL || export_ == NULL || out_type == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    if (export_->kind != WAED_KIND_FUNCTION)
    {
        snprintf(error_message, sizeof(error_message),
                 "Export is not a function: %s", export_->name);
        return WAED_ERROR_INVALID_SECTION;
    }

    uint32_t func_index = export_->index;
    uint32_t type_index = 0;

    // Determine if the function is imported or locally defined
    uint32_t imported_funcs = 0;
    for (size_t i = 0; i < module->import_count; i++)
    {
        if (module->imports[i].kind == WAED_KIND_FUNCTION)
        {
            imported_funcs++;
        }
    }

    if (func_index < imported_funcs)
    {
        // Imported function
        uint32_t import_idx = 0;
        for (size_t i = 0; i < module->import_count; i++)
        {
            if (module->imports[i].kind == WAED_KIND_FUNCTION)
            {
                if (import_idx == func_index)
                {
                    type_index = module->imports[i].type_index;
                    break;
                }
                import_idx++;
            }
        }
    }
    else
    {
        // Locally defined function
        uint32_t local_idx = func_index - imported_funcs;
        if (local_idx >= module->function_count)
        {
            snprintf(error_message, sizeof(error_message),
                     "Invalid function index: %u", func_index);
            return WAED_ERROR_INVALID_SECTION;
        }
        type_index = module->function_type_indices[local_idx];
    }

    // Get the function type
    if (type_index >= module->type_count)
    {
        snprintf(error_message, sizeof(error_message),
                 "Invalid type index: %u", type_index);
        return WAED_ERROR_INVALID_SECTION;
    }

    out_type->param_count = module->types[type_index].param_count;
    out_type->param_types = module->types[type_index].param_types;
    out_type->result_count = module->types[type_index].result_count;
    out_type->result_types = module->types[type_index].result_types;

    return WAED_SUCCESS;
}

// Get the function type of an import
waed_error_t waed_module_get_import_function_type(const waed_module_t *module,
                                                  const waed_import_t *import_,
                                                  waed_function_type_t *out_type)
{
    if (module == NULL || import_ == NULL || out_type == NULL)
    {
        snprintf(error_message, sizeof(error_message), "Invalid argument: NULL pointer");
        return WAED_ERROR_INVALID_ARGUMENT;
    }

    if (import_->kind != WAED_KIND_FUNCTION)
    {
        snprintf(error_message, sizeof(error_message),
                 "Import is not a function: %s.%s",
                 import_->module_name, import_->field_name);
        return WAED_ERROR_INVALID_SECTION;
    }

    uint32_t type_index = import_->type_index;
    if (type_index >= module->type_count)
    {
        snprintf(error_message, sizeof(error_message),
                 "Invalid type index: %u", type_index);
        return WAED_ERROR_INVALID_SECTION;
    }

    out_type->param_count = module->types[type_index].param_count;
    out_type->param_types = module->types[type_index].param_types;
    out_type->result_count = module->types[type_index].result_count;
    out_type->result_types = module->types[type_index].result_types;

    return WAED_SUCCESS;
}

// Get the last error message
const char *waed_get_error_message(void)
{
    return error_message;
}