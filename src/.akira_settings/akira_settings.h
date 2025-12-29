/**
* @file akira_settings.h
* @brief Key-value settings storage with NVS backend
*
* GET/SET/DELETE/LIST functions
* Stored Keys in a registry
*
*/

#ifndef AKIRA_SETTINGS_H
#define AKIRA_SETTINGS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#define DEFAULT_MAX_KEYS 32
#define DEFAULT_MAX_VALUE_LEN 32
#define REGISTRY_COUNTER_ID         0
#define REGISTRY_MAX_VALUE_LEN_ID     1 
#define REGISTRY_MAX_KEYS_ID          2
#define REGISTRY_KEYS_START         3
#define REGISTRY_KEYS_SIZE       100
// Minimum encrypted: 2+12+16+1=31 bytes → 42 chars base64
#define MINIMUM_ENCRYPTED_LEN 42

/* Helper macro to convert hex string to byte array */
#define HEX_TO_BYTE(h1, h2) \
    ((((h1) >= '0' && (h1) <= '9') ? ((h1) - '0') : \
      ((h1) >= 'a' && (h1) <= 'f') ? ((h1) - 'a' + 10) : \
      ((h1) >= 'A' && (h1) <= 'F') ? ((h1) - 'A' + 10) : 0) << 4 | \
     (((h2) >= '0' && (h2) <= '9') ? ((h2) - '0') : \
      ((h2) >= 'a' && (h2) <= 'f') ? ((h2) - 'a' + 10) : \
      ((h2) >= 'A' && (h2) <= 'F') ? ((h2) - 'A' + 10) : 0))

// Iterator for listing all keys
typedef struct {
    void* ptr; 
    char* key; // Current key 
    char* value; // Current value
    size_t key_buffer_size;
    size_t value_buffer_size;
} settings_iterator_t;

typedef enum{
    AKIRA_SETTINGS_STORAGE_FLASH = 0,
    AKIRA_SETTINGS_STORAGE_SD,
    AKIRA_SETTINGS_STORAGE_AUTO
} settings_storage_type_t;

typedef struct {
    char **keys;
    size_t count;
    size_t index;
} iter_data_t;

typedef enum {
    AKIRA_SETTINGS_OP_SET,
    AKIRA_SETTINGS_OP_GET,
    AKIRA_SETTINGS_OP_DELETE,
    AKIRA_SETTINGS_OP_CLEAR,
    AKIRA_SETTINGS_OP_LIST,
    AKIRA_SETTINGS_OP_RESIZE
} settings_op_type_t;


typedef void (*settings_wq_callback_t)(int result, void *user_data);

/**
 * Initialze settings
 * 
 * @return 0 on success, negative on failure
*/
int akira_settings_init(void);

/**
 *  Get value from Key
 * 
 * @param key - Key form which to get value
 * @param value - Output buffer for value
 * @param max_len - Size of output buffer
 * @return 0 on success, negative on error
 */
int akira_settings_get(const char *key, char *value, uint16_t max_len);


/**
 * Set Key to Value
 * 
 * @param key - Key
 * @param value - Value to store
 * @return 0 on success, negative on error
 */
int akira_settings_set(const char *key, const char *value);

/**
 * Remove the key and the value associated
 * 
 * @param key - Key to remove
 * @return 0 on success, negative on error
 */
int akira_settings_delete(const char *key);

/**
 * List all settings
 * 
 * @param iter - Iterator buffer to get Keys and Values
 * @return 0 on success, 1 when done, negative on error
 */
int akira_settings_list(settings_iterator_t *iter);
/**
 * Change limits 
 * 
 * @param new_max_value_len - New max lenght for value 
 * @param new_max_keys - New max amount of keys
 * @return 0 on success, 1 when done, negative on error
 */
int akira_settings_resize_limits(uint16_t new_max_value_len, uint16_t new_max_keys);

/**
 * Set encrypted value
 * 
 * @param key - Key
 * @param value - Plaintext value to encrypt and store
 * @return 0 on success, negative on error
 */
int akira_settings_set_encrypted(const char *key, const char *value);


#endif //AKIRA_SETTINGS_H