// cli.c - CLI tool for manipulating WebAssembly custom sections
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include "waed.h"
#include "version.h" // Include the auto-generated version header

#define MAX_SECTION_NAME_LEN 256
#define MAX_HEX_DUMP_BYTES 10240

void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS] COMMAND WASM_FILE\n\n", prog_name);
    printf("Commands:\n");
    printf("  list                   List all custom sections in the WebAssembly module\n");
    printf("  add                    Add a custom section from a file\n");
    printf("  get                    Extract a custom section to a file or stdout\n\n");
    printf("Options:\n");
    printf("  -h, --help             Display this help message and exit\n");
    printf("  -v, --version          Display version information and exit\n");
    printf("  -x[N], --hex[=N]       Display section content as hex dump (max N bytes, default 32)\n");
    printf("  -n, --name=NAME        Set custom section name (required for 'get', optional for 'add')\n");
    printf("  -f, --file=FILE        Input file for 'add' command\n");
    printf("  -o, --output=FILE      Output file for 'add' and 'get' commands\n");
}

void print_version(void)
{
    printf("waed version %s\n", TOOL_VERSION);
}

// Utility function to print a hexdump of binary data
void print_hexdump(const uint8_t *data, size_t size, size_t max_bytes)
{
    size_t bytes_to_show = (size < max_bytes) ? size : max_bytes;

    printf("Content (%zu bytes, showing first %zu):\n", size, bytes_to_show);
    for (size_t i = 0; i < bytes_to_show; i++)
    {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }

    if (bytes_to_show % 16 != 0)
    {
        printf("\n");
    }

    if (bytes_to_show < size)
    {
        printf("... (%zu more bytes)\n", size - bytes_to_show);
    }
}

// Utility function to read a file into memory
uint8_t *read_file(const char *path, size_t *out_size)
{
    if (path == NULL || out_size == NULL)
    {
        fprintf(stderr, "Error: Invalid parameters to read_file\n");
        return NULL;
    }

    FILE *file = fopen(path, "rb");
    if (!file)
    {
        fprintf(stderr, "Error: Could not open file %s: %s\n", path, strerror(errno));
        return NULL;
    }

    // Get file size
    if (fseek(file, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "Error: Could not seek to end of file: %s\n", strerror(errno));
        fclose(file);
        return NULL;
    }

    long file_size = ftell(file);

    if (fseek(file, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "Error: Could not seek back to start of file: %s\n", strerror(errno));
        fclose(file);
        return NULL;
    }


    if (file_size < 0)
    {
        fclose(file);
        fprintf(stderr, "Error: Could not determine file size: %s\n", strerror(errno));
        return NULL;
    }

    // Allocate buffer and read file
    uint8_t *buffer = malloc((size_t)file_size);
    if (!buffer)
    {
        fclose(file);
        fprintf(stderr, "Error: Memory allocation failed for %ld bytes\n", file_size);
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, (size_t)file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size)
    {
        free(buffer);
        fprintf(stderr, "Error: Could not read entire file (read %zu of %ld bytes): %s\n",
                bytes_read, file_size, strerror(errno));
        return NULL;
    }

    *out_size = (size_t)file_size;
    return buffer;
}

// Utility function to write data to a file
int write_file(const char *path, const uint8_t *data, size_t size)
{
    if (path == NULL || data == NULL)
    {
        fprintf(stderr, "Error: Invalid parameters to write_file\n");
        return 0;
    }

    FILE *file = fopen(path, "wb");
    if (!file)
    {
        fprintf(stderr, "Error: Could not open file %s for writing: %s\n", path, strerror(errno));
        return 0;
    }

    size_t bytes_written = fwrite(data, 1, size, file);
    fclose(file);

    if (bytes_written != size)
    {
        fprintf(stderr, "Error: Could not write entire content to file: %s\n", strerror(errno));
        return 0;
    }

    return 1;
}

// Safe string comparison
int safe_strcmp(const char *s1, const char *s2, size_t max_len)
{
    if (s1 == NULL || s2 == NULL)
    {
        return -1; // Error condition
    }

    return strncmp(s1, s2, max_len);
}

int cmd_list_sections(const char *wasm_file, int hex_dump, int hex_dump_bytes)
{
    if (wasm_file == NULL)
    {
        fprintf(stderr, "Error: No WebAssembly file specified\n");
        return 1;
    }

    // Load the WebAssembly module
    waed_module_t *module;
    waed_error_t result = waed_module_load_file(wasm_file, &module);

    if (result != WAED_SUCCESS)
    {
        fprintf(stderr, "Error loading module: %s\n", waed_get_error_message());
        return 1;
    }

    // Get and print custom sections
    uint32_t custom_count = waed_module_get_custom_section_count(module);

    if (custom_count == 0)
    {
        printf("No custom sections found in the module.\n");
        waed_module_destroy(module);
        return 0;
    }

    printf("%-5s %-30s %s\n", "INDEX", "NAME", "SIZE");
    printf("%-5s %-30s %s\n", "-----", "------------------------------", "--------");

    for (uint32_t i = 0; i < custom_count; i++)
    {
        waed_custom_section_t section;
        result = waed_module_get_custom_section(module, i, &section);

        if (result != WAED_SUCCESS)
        {
            fprintf(stderr, "Error getting custom section %u: %s\n", i, waed_get_error_message());
            continue;
        }

        printf("%-5u %-30s %zu\n", i, section.name, section.content_size);

        if (hex_dump)
        {
            print_hexdump(section.content, section.content_size, (size_t)hex_dump_bytes);
            printf("\n");
        }
    }

    // Clean up
    waed_module_destroy(module);
    return 0;
}

int cmd_add_section(const char *wasm_file, const char *input_file, const char *section_name, const char *output_file)
{
    if (wasm_file == NULL || input_file == NULL || section_name == NULL || output_file == NULL)
    {
        fprintf(stderr, "Error: Missing required parameters for add command\n");
        return 1;
    }

    // Load the WebAssembly module
    waed_module_t *module;
    waed_error_t result = waed_module_load_file(wasm_file, &module);

    if (result != WAED_SUCCESS)
    {
        fprintf(stderr, "Error loading module: %s\n", waed_get_error_message());
        return 1;
    }

    // Read the input file
    size_t data_size;
    uint8_t *data = read_file(input_file, &data_size);

    if (!data)
    {
        waed_module_destroy(module);
        return 1;
    }

    // Add the custom section
    result = waed_module_add_custom_section(module, section_name, data, data_size);

    if (result != WAED_SUCCESS)
    {
        fprintf(stderr, "Error adding custom section: %s\n", waed_get_error_message());
        free(data);
        waed_module_destroy(module);
        return 1;
    }

    // Save the modified module
    result = waed_module_save_file(module, output_file);

    if (result != WAED_SUCCESS)
    {
        fprintf(stderr, "Error saving modified module: %s\n", waed_get_error_message());
        free(data);
        waed_module_destroy(module);
        return 1;
    }

    printf("Section '%s' added successfully to %s\n", section_name, output_file);

    // Clean up
    free(data);
    waed_module_destroy(module);
    return 0;
}

int cmd_get_section(const char *wasm_file, const char *section_name, const char *output_file, int hex_dump, int hex_dump_bytes)
{
    if (wasm_file == NULL || section_name == NULL)
    {
        fprintf(stderr, "Error: Missing required parameters for get command\n");
        return 1;
    }

    // Load the WebAssembly module
    waed_module_t *module;
    waed_error_t result = waed_module_load_file(wasm_file, &module);

    if (result != WAED_SUCCESS)
    {
        fprintf(stderr, "Error loading module: %s\n", waed_get_error_message());
        return 1;
    }

    // Find the requested section
    uint32_t custom_count = waed_module_get_custom_section_count(module);
    waed_custom_section_t section;
    int found = 0;

    for (uint32_t i = 0; i < custom_count; i++)
    {
        waed_custom_section_t current_section;
        result = waed_module_get_custom_section(module, i, &current_section);

        if (result != WAED_SUCCESS)
        {
            continue;
        }

        if (safe_strcmp(current_section.name, section_name, MAX_SECTION_NAME_LEN) == 0)
        {
            section = current_section;
            found = 1;
            break;
        }
    }

    if (!found)
    {
        fprintf(stderr, "Error: Custom section '%s' not found in the module\n", section_name);
        waed_module_destroy(module);
        return 1;
    }

    // Output the section content
    if (output_file)
    {
        // Write to file
        if (!write_file(output_file, section.content, section.content_size))
        {
            waed_module_destroy(module);
            return 1;
        }

        printf("Section '%s' extracted to %s (%zu bytes)\n",
               section_name, output_file, section.content_size);
    }
    else
    {
        // Write to stdout (as hex dump if requested, or raw otherwise)
        if (hex_dump)
        {
            print_hexdump(section.content, section.content_size, (size_t)hex_dump_bytes);
        }
        else
        {
            // Raw output to stdout
            if (section.content != NULL && section.content_size > 0)
            {
                if (fwrite(section.content, 1, section.content_size, stdout) != section.content_size)
                {
                    fprintf(stderr, "Error: Failed to write section content to stdout\n");
                }
            }
        }
    }

    // Clean up
    waed_module_destroy(module);
    return 0;
}

int safe_parse_int(const char *str, int default_value, int min_value, int max_value)
{
    if (str == NULL || *str == '\0')
    {
        return default_value;
    }

    char *endptr;
    errno = 0;
    long val = strtol(str, &endptr, 10);

    // Check for errors
    if (errno != 0 || endptr == str || *endptr != '\0' ||
        val < min_value || val > max_value)
    {
        return default_value;
    }

    return (int)val;
}

char *safe_strdup(const char *str)
{
    if (str == NULL)
    {
        return NULL;
    }

    size_t len = strlen(str) + 1;
    char *new_str = malloc(len);

    if (new_str != NULL)
    {
        memcpy(new_str, str, len);
    }

    return new_str;
}

int main(int argc, char *argv[])
{
    // Default values
    char *section_name = NULL;
    char *input_file = NULL;
    char *output_file = NULL;
    int hex_dump = 0;
    int hex_dump_bytes = 32;
    int should_free_output_file = 0;

    // Command line options
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"hex", optional_argument, 0, 'x'},
        {"name", required_argument, 0, 'n'},
        {"output", required_argument, 0, 'o'},
        {"file", required_argument, 0, 'f'},
        {0, 0, 0, 0}};

    int opt;
    int option_index = 0;

    // Reset getopt
    optind = 1;

    while ((opt = getopt_long(argc, argv, "hvx::n:o:f:", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'v':
            print_version();
            return 0;
        case 'x':
            hex_dump = 1;
            if (optarg)
            {
                hex_dump_bytes = safe_parse_int(optarg, 32, 1, MAX_HEX_DUMP_BYTES);
            }
            break;
        case 'n':
            free(section_name); // Free any previous allocation
            section_name = safe_strdup(optarg);
            if (!section_name && optarg)
            {
                fprintf(stderr, "Error: Memory allocation failed for section name\n");
                return 1;
            }
            break;
        case 'o':
            free(output_file); // Free any previous allocation
            output_file = safe_strdup(optarg);
            if (!output_file && optarg)
            {
                fprintf(stderr, "Error: Memory allocation failed for output file\n");
                free(section_name);
                return 1;
            }
            break;
        case 'f':
            free(input_file); // Free any previous allocation
            input_file = safe_strdup(optarg);
            if (!input_file && optarg)
            {
                fprintf(stderr, "Error: Memory allocation failed for input file\n");
                free(section_name);
                free(output_file);
                return 1;
            }
            break;
        default:
            fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
            free(section_name);
            free(input_file);
            free(output_file);
            return 1;
        }
    }

    // Check for command and mandatory wasm_file
    if (optind >= argc)
    {
        fprintf(stderr, "Error: No command specified\n");
        print_usage(argv[0]);
        free(section_name);
        free(input_file);
        free(output_file);
        return 1;
    }

    // Parse command
    const char *cmd_str = argv[optind++];

    // Get WASM file argument
    if (optind >= argc)
    {
        fprintf(stderr, "Error: No WebAssembly file specified\n");
        print_usage(argv[0]);
        free(section_name);
        free(input_file);
        free(output_file);
        return 1;
    }

    const char *wasm_file = argv[optind];

    int result = 1; // Default to error

    // Command-specific validation and execution
    if (safe_strcmp(cmd_str, "list", 5) == 0)
    {
        result = cmd_list_sections(wasm_file, hex_dump, hex_dump_bytes);
    }
    else if (safe_strcmp(cmd_str, "add", 4) == 0)
    {
        if (!input_file)
        {
            fprintf(stderr, "Error: No input file specified for 'add' command\n");
            fprintf(stderr, "Use -f/--file to specify the input file\n");
            goto cleanup;
        }

        if (!section_name)
        {
            // Use the filename as section name if not specified
            const char *basename = strrchr(input_file, '/');
            if (!basename)
            {
                basename = strrchr(input_file, '\\');
            }

            const char *name_to_use = basename ? (basename + 1) : input_file;
            section_name = safe_strdup(name_to_use);

            if (!section_name)
            {
                fprintf(stderr, "Error: Memory allocation failed for section name\n");
                goto cleanup;
            }
        }

        if (!output_file)
        {
            // Default output filename
            size_t base_len = strlen(wasm_file);
            size_t needed_size = base_len + 15; // +15 for ".modified.wasm\0"

            output_file = malloc(needed_size);
            if (output_file)
            {
                if (snprintf(output_file, needed_size, "%s.modified.wasm", wasm_file) < 0)
                {
                    fprintf(stderr, "Error: Failed to create output filename\n");
                    free(output_file);
                    output_file = NULL;
                    goto cleanup;
                }
                should_free_output_file = 1;
            }
            else
            {
                fprintf(stderr, "Error: Memory allocation failed\n");
                goto cleanup;
            }
        }

        result = cmd_add_section(wasm_file, input_file, section_name, output_file);
    }
    else if (safe_strcmp(cmd_str, "get", 4) == 0)
    {
        if (!section_name)
        {
            fprintf(stderr, "Error: No section name specified for 'get' command\n");
            fprintf(stderr, "Use -n/--name to specify the section name\n");
            goto cleanup;
        }

        result = cmd_get_section(wasm_file, section_name, output_file, hex_dump, hex_dump_bytes);
    }
    else
    {
        fprintf(stderr, "Error: Unknown command '%s'\n", cmd_str);
        print_usage(argv[0]);
        goto cleanup;
    }

cleanup:
    // Free allocated memory
    free(section_name);
    free(input_file);
    if (should_free_output_file)
    {
        free(output_file);
    }
    else
    {
        free(output_file);
    }

    return result;
}