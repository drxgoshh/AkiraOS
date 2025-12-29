#include "akira_settings.h"
#include "fs_manager.h"
#include <zephyr/kernel.h>
#include <zephyr/fs/nvs.h>
#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>
#include <zephyr/devicetree.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/base64.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef CONFIG_AKIRA_SETTINGS_ENCRYPTION
#include <mbedtls/gcm.h>
#include <mbedtls/platform.h>
#include <zephyr/random/random.h>
#endif

LOG_MODULE_REGISTER(akira_settings, CONFIG_LOG_DEFAULT_LEVEL);

/*----------------ENCRYPTION FUNCTIONS------------------------*/

#ifdef CONFIG_AKIRA_SETTINGS_ENCRYPTION

/* Magic bytes to identify encrypted data */
#define ENCRYPTION_MAGIC 0xAE01
#define MAGIC_SIZE 2
#define IV_SIZE 12
#define TAG_SIZE 16

static struct {
    mbedtls_gcm_context gcm;
    bool initialized;
} crypto_ctx = {
    .initialized = false
};

static uint8_t ENCRYPTION_KEY[32];

static int parse_hex_key(void) {
    // Pointer to encryption key set in KConfig
    const char *hex = CONFIG_AKIRA_SETTINGS_ENCRYPTION_KEY_HEX; 
    
    if (strlen(hex) != 64) {
        return -EINVAL;
    }

    for (int i = 0; i < 32; i++) {
        ENCRYPTION_KEY[i] = HEX_TO_BYTE(hex[i*2], hex[i*2+1]);
    }
    
    return 0;
}

static int crypto_init(void) {
    if (crypto_ctx.initialized) {
        return 0;
    }
    
    int ret = parse_hex_key();
    if (ret != 0) {
        LOG_ERR("Failed to parse encryption key");
        return ret;
    }

    mbedtls_gcm_init(&crypto_ctx.gcm);
    
    /* Set up AES-256-GCM with hardware acceleration */
    ret = mbedtls_gcm_setkey(&crypto_ctx.gcm, 
                                  MBEDTLS_CIPHER_ID_AES,
                                  ENCRYPTION_KEY, 
                                  256);
    
    if (ret != 0) {
        LOG_ERR("Failed to set encryption key: %d", ret);
        mbedtls_gcm_free(&crypto_ctx.gcm);
        return -EINVAL;
    }
    
    crypto_ctx.initialized = true;
    LOG_INF("AES-256-GCM encryption initialized (HW accelerated)");
    
    return 0;
}

/**
 * @brief Check if data has encryption magic header
 */
static bool crypto_is_encrypted(const uint8_t *data, size_t len) {
    if (len < MAGIC_SIZE) {
        return false;
    }
    
    uint16_t magic = (data[0] << 8) | data[1];
    return (magic == ENCRYPTION_MAGIC);
}

/**
 * @brief Encrypt value with magic header and authentication
 * @param plaintext Input plaintext string
 * @param output Output buffer for [MAGIC][encrypted data]
 * @param max_len Maximum output buffer size
 * @return Total data length on success, negative errno on failure
 */
static int crypto_encrypt(const char *plaintext, uint8_t *output, size_t max_len) {
    if (!crypto_ctx.initialized) {
        LOG_ERR("Crypto not initialized");
        return -EINVAL;
    }
    
    if (!plaintext || !output) {
        return -EINVAL;
    }
    
    size_t plain_len = strlen(plaintext);
    
    /* Format: [2-byte MAGIC][12-byte IV][encrypted data][16-byte tag] */
    size_t required_len = MAGIC_SIZE + IV_SIZE + plain_len + TAG_SIZE;
    if (required_len > max_len) {
        LOG_ERR("Buffer too small: need %zu, have %zu", required_len, max_len);
        return -E2BIG;
    }
    
    /* Write magic header */
    output[0] = (ENCRYPTION_MAGIC >> 8) & 0xFF;
    output[1] = ENCRYPTION_MAGIC & 0xFF;
    
    /* Generate random IV */
    uint8_t iv[IV_SIZE];
    sys_rand_get(iv, IV_SIZE);
    memcpy(output + MAGIC_SIZE, iv, IV_SIZE);
    
    /* Allocate space for auth tag */
    uint8_t tag[TAG_SIZE];
    
    /* Encrypt: plaintext → output after [MAGIC][IV] */
    int ret = mbedtls_gcm_crypt_and_tag(
        &crypto_ctx.gcm,
        MBEDTLS_GCM_ENCRYPT,
        plain_len,
        iv, IV_SIZE,
        NULL, 0,  /* No additional authenticated data */
        (const unsigned char *)plaintext,
        output + MAGIC_SIZE + IV_SIZE,  /* Write after magic and IV */
        TAG_SIZE,
        tag
    );
    
    if (ret != 0) {
        LOG_ERR("Encryption failed: %d", ret);
        return -EIO;
    }
    
    /* Append auth tag */
    memcpy(output + MAGIC_SIZE + IV_SIZE + plain_len, tag, TAG_SIZE);
    
    return required_len;
}

/**
 * @brief Check if data is encrypted and decrypt if needed
 * @param input Input data (may be encrypted or plaintext)
 * @param input_len Length of input data
 * @param output Output buffer for plaintext
 * @param max_len Maximum output buffer size
 * @return 0 on success, negative errno on failure
 */
static int crypto_decrypt(const uint8_t *input, size_t input_len,
                                    char *output, size_t max_len) {
    
    /* Format: [MAGIC][IV][data][TAG] */
    if (input_len < MAGIC_SIZE + IV_SIZE + TAG_SIZE) {
        LOG_ERR("Encrypted data too short: %zu", input_len);
        return -EINVAL;
    }
    
    /* Extract components (skip magic) */
    const uint8_t *iv = input + MAGIC_SIZE;
    const uint8_t *encrypted_data = input + MAGIC_SIZE + IV_SIZE;
    size_t data_len = input_len - MAGIC_SIZE - IV_SIZE - TAG_SIZE;
    const uint8_t *tag = input + MAGIC_SIZE + IV_SIZE + data_len;
    
    if (data_len >= max_len) {
        LOG_ERR("Output buffer too small: need %zu, have %zu", data_len + 1, max_len);
        return -E2BIG;
    }
    
    /* Decrypt and verify */
    int ret = mbedtls_gcm_auth_decrypt(
        &crypto_ctx.gcm,
        data_len,
        iv, IV_SIZE,
        NULL, 0,  /* No additional authenticated data */
        tag, TAG_SIZE,
        encrypted_data,
        (unsigned char *)output
    );
    
    if (ret != 0) {
        if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED) {
            LOG_ERR("Authentication failed - data tampered!");
        } else {
            LOG_ERR("Decryption failed: %d", ret);
        }
        return -EIO;
    }
    
    output[data_len] = '\0';
    
    return 0;
}

#else 

/* Encryption disabled - pass through functions */

static int crypto_init(void) {
    LOG_INF("Encryption disabled (plaintext mode)");
    return 0;
}

static bool crypto_is_encrypted(const uint8_t *data, size_t len) {
    return false;
}

static int crypto_encrypt(const char *plaintext, uint8_t *output, size_t max_len) {
    LOG_INF("Encryption disabled (plaintext mode)");
    return 0;
}

static int crypto_decrypt(const uint8_t *input, size_t input_len, char *output, size_t max_len) {
    LOG_INF("Encryption disabled (plaintext mode)");
    return 0;
}

#endif /* CONFIG_AKIRA_SETTINGS_ENCRYPTION */

static K_MUTEX_DEFINE(akira_settings_mutex);

K_THREAD_STACK_DEFINE(work_stack, 2048);

struct akira_setting_work {
    struct k_work work; 
    settings_op_type_t type;
    char *key;
    char *value;
    uint16_t max_len; 
    
    /* Completion signaling */
    settings_wq_callback_t callback;
    void *user_data;
    struct k_sem *completion_sem;
    int *result_ptr;
};

static struct {
    struct nvs_fs nvs;
    settings_storage_type_t type;
    bool initialized;
    bool sd_available;
    int max_keys;
    int max_value_len;

    struct k_work_q work_queue;
} storage = {
    .type = AKIRA_SETTINGS_STORAGE_FLASH,
    .initialized = false,
    .sd_available = false,
    .max_keys = CONFIG_AKIRA_SETTINGS_MAX_KEYS,
    .max_value_len = CONFIG_AKIRA_SETTINGS_MAX_VALUE_LEN
};

/*----------------------------HELPER FUNCTIONS--------------------------------------------------*/

static int resize_limits_internal(uint16_t new_max_value_len, uint16_t new_max_keys) {
    if (new_max_keys >= REGISTRY_KEYS_SIZE || !new_max_value_len || !new_max_keys) {
        return -EINVAL;
    }

    uint16_t old_max_value_len;
    int ret = nvs_read(&storage.nvs, REGISTRY_MAX_VALUE_LEN_ID, 
                       &old_max_value_len, sizeof(old_max_value_len));
    if (ret < 0) {
        return ret;
    }

    uint16_t old_max_keys;
    ret = nvs_read(&storage.nvs, REGISTRY_MAX_KEYS_ID, 
                   &old_max_keys, sizeof(old_max_keys));
    if (ret < 0) {
        return ret;
    }

    uint16_t registry_counter;
    ret = nvs_read(&storage.nvs, REGISTRY_COUNTER_ID, 
                   &registry_counter, sizeof(registry_counter));
    
    // Validation
    if (ret >= 0 && registry_counter > 0) {
        if (new_max_keys < registry_counter) {
            LOG_ERR("Cannot reduce max_keys to %d: %d keys exist", 
                    new_max_keys, registry_counter);
            return -EINVAL;
        }
        if (new_max_value_len < old_max_value_len) {
            LOG_ERR("Cannot shrink max_value_len: %d → %d", 
                    old_max_value_len, new_max_value_len);
            return -EINVAL;
        }
    }

    // Write new limits
    ret = nvs_write(&storage.nvs, REGISTRY_MAX_VALUE_LEN_ID, 
                    &new_max_value_len, sizeof(new_max_value_len));
    if (ret < 0) {
        return ret;
    }

    ret = nvs_write(&storage.nvs, REGISTRY_MAX_KEYS_ID, 
                    &new_max_keys, sizeof(new_max_keys));
    if (ret < 0) {
        return ret;
    }

    // Update in-memory config
    storage.max_value_len = new_max_value_len;
    storage.max_keys = new_max_keys;

    LOG_INF("Resized: max_value_len %d→%d, max_keys %d→%d",
            old_max_value_len, new_max_value_len, 
            old_max_keys, new_max_keys);
    
    return 0;
}

static int handle_config_mismatch(uint16_t stored_max_value_len, 
                                   uint16_t stored_max_keys, 
                                   uint16_t registry_counter) {
    bool config_changed = false;
    uint16_t final_max_value_len = storage.max_value_len;
    uint16_t final_max_keys = storage.max_keys;

    // Check value length mismatch
    if (stored_max_value_len != storage.max_value_len) {
        LOG_INF("Config mismatch: max_value_len %d → %d", 
                stored_max_value_len, storage.max_value_len);

        if (storage.max_value_len < stored_max_value_len) {
            // SHRINKING: Not allowed
            LOG_ERR("Cannot shrink max_value_len! Keeping old value: %d", 
                    stored_max_value_len);
            final_max_value_len = stored_max_value_len;
            config_changed = true;
        } else {
            // GROWING: Try to resize (safe during init - no work queue needed)
            LOG_INF("Attempting to resize to new limits...");
            int ret = resize_limits_internal(storage.max_value_len, storage.max_keys);
            if (ret < 0) {
                LOG_ERR("Resize failed! Reverting to old limits");
                final_max_value_len = stored_max_value_len;
                final_max_keys = stored_max_keys;
                config_changed = true;
            } else {
                LOG_INF("Successfully resized to new limits");
                return 0; // Success
            }
        }
    }

    // Check max keys mismatch
    if (stored_max_keys != storage.max_keys) {
        LOG_INF("Config mismatch: max_keys %d → %d", 
                stored_max_keys, storage.max_keys);

        if (storage.max_keys < stored_max_keys && registry_counter > storage.max_keys) {
            // SHRINKING with existing data: Not allowed
            LOG_ERR("Cannot shrink max_keys to %d (have %d keys). Keeping: %d",
                    storage.max_keys, registry_counter, stored_max_keys);
            final_max_keys = stored_max_keys;
            config_changed = true;
        }
    }

    // Apply reverted limits if needed
    if (config_changed) {
        storage.max_value_len = final_max_value_len;
        storage.max_keys = final_max_keys;

        // Write back to NVS
        int ret = nvs_write(&storage.nvs, REGISTRY_MAX_VALUE_LEN_ID, 
                           &final_max_value_len, sizeof(final_max_value_len));
        if (ret < 0) {
            LOG_ERR("Failed to write max_value_len to NVS");
            return -EIO;
        }

        ret = nvs_write(&storage.nvs, REGISTRY_MAX_KEYS_ID, 
                       &final_max_keys, sizeof(final_max_keys));
        if (ret < 0) {
            LOG_ERR("Failed to write max_keys to NVS");
            return -EIO;
        }

        LOG_INF("Config reverted in NVS: max_value_len=%d, max_keys=%d",
                final_max_value_len, final_max_keys);
    }

    return 0;
}


static void free_keys_array(char **keys, uint16_t count) {
    if (!keys) return;
    
    for (uint16_t i = 0; i < count; i++) {
        if (keys[i]) {
            k_free(keys[i]);
        }
    }
    k_free(keys);
}

static int init_sd(void){
    int ret = fs_manager_exists("/SD:");
    if (ret <= 0) {
        LOG_WRN("SD card not available: %d", ret);
        return -ENODEV;
    }

    ret = fs_manager_mkdir("/SD:/settings");
    if (ret != 0) {
        LOG_ERR("Failed to create settings directory: %d", ret);
        return ret;
    }

    storage.sd_available = true;
    LOG_INF("SD card type initialized");
    return 0;
}

static int init_flash(void){
    const struct device *flash_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
    
    if (!device_is_ready(flash_dev)) {
        LOG_ERR("Flash device not ready");
        return -ENODEV;
    }
    
    storage.nvs.flash_device = flash_dev;
    storage.nvs.offset = FIXED_PARTITION_OFFSET(akira_settings_nvs_partition);
    storage.nvs.sector_size = 4096;
    storage.nvs.sector_count = 16;
    
    int ret = nvs_mount(&storage.nvs);
    if (ret) {
        LOG_ERR("NVS mount failed: %d", ret);
        return ret;
    }

    uint16_t registry_counter;
    uint16_t stored_max_value_len;
    uint16_t stored_max_keys;
    // Check if registry is initiliazed
    ret = nvs_read(&storage.nvs, REGISTRY_COUNTER_ID, &registry_counter, sizeof(registry_counter));
    if (ret < 0) {
        LOG_INF("Initializing registry counter (first boot)");

        uint16_t initial_counter = 0;
        ret = nvs_write(&storage.nvs, REGISTRY_COUNTER_ID, &initial_counter, sizeof(uint16_t));
        if (ret < 0) {
            LOG_ERR("Failed to initialize registry counter: %d", ret);
            return ret;
        }

        uint16_t max_val_len = (uint16_t)storage.max_value_len;
        uint16_t max_keys_val = (uint16_t)storage.max_keys;
        
        ret = nvs_write(&storage.nvs, REGISTRY_MAX_VALUE_LEN_ID, &max_val_len, sizeof(max_val_len));
        if (ret < 0) {
            LOG_ERR("Failed to store max_value_len: %d", ret);
            return ret;
        }
        
        ret = nvs_write(&storage.nvs, REGISTRY_MAX_KEYS_ID, &max_keys_val, sizeof(max_keys_val));
        if (ret < 0) {
            LOG_ERR("Failed to store max_keys: %d", ret);
            return ret;
        }

        LOG_INF("Initialized: max_value_len=%d, max_keys=%d", storage.max_value_len, storage.max_keys);
    } else {
        LOG_INF("Existing storage found: %d keys", registry_counter);
        
        ret = nvs_read(&storage.nvs, REGISTRY_MAX_VALUE_LEN_ID, &stored_max_value_len, sizeof(stored_max_value_len));
        if (ret < 0) {
            LOG_WRN("Couldn't read REGISTRY_MAX_VALUE_LEN_ID");
            return -1;
        }
        
        ret = nvs_read(&storage.nvs, REGISTRY_MAX_KEYS_ID, &stored_max_keys, sizeof(stored_max_keys));
        if (ret < 0) {
            LOG_WRN("Couldn't read REGISTRY_MAX_KEYS_ID");
            return -1;
        }
        // Check for config changes
        ret = handle_config_mismatch(stored_max_value_len, stored_max_keys, registry_counter);
        if (ret < 0) {
            LOG_ERR("Failed to handle config mismatch: %d", ret);
            return ret;
        }
    }

    LOG_INF("Flash type initialized (NVS mounted)");
    return 0;
}

/*----------------------------REGISTRY FUNCTIONS--------------------------------------------------*/

/**
 * REGISTRY OVERVIEW:
 * The registry is an index that maps key names to storage locations.
 * 
 * Flash Storage Layout:
 *   - REGISTRY_COUNTER_ID:     Number of registered keys
 *   - REGISTRY_KEYS_START+0:   First key name string
 *   - REGISTRY_KEYS_START+1:   Second key name string
 *   - ...
 *   - REGISTRY_KEYS_START+N + REGISTRY_KEYS_SIZE: Actual values start here
 * 
 * Why we need it:
 *   - NVS uses numeric IDs, but users want string keys like "wifi/ssid"
 *   - Registry translates: "wifi/ssid" (index 5) -> NVS ID (REGISTRY_KEYS_START + 5 + REGISTRY_KEYS_SIZE)
 * 
 * SD Storage:
 *   - Registry stored in /SD:/settings/.registry.txt as newline-separated key names
*/

static int registry_get_all_keys(char ***out_keys, uint16_t *out_count) {
    if (!out_keys || !out_count) {
        return -EINVAL;
    }
    
    *out_keys = NULL;
    *out_count = 0;
    int ret;
    uint16_t registry_counter = 0;
    char **keys = NULL;

    if (storage.type == AKIRA_SETTINGS_STORAGE_FLASH) {
        
        ret = nvs_read(&storage.nvs, REGISTRY_COUNTER_ID, &registry_counter, sizeof(registry_counter));
        if (ret < 0) {
            LOG_ERR("Failed to read registry counter");
            return ret;
        }
        
        keys = k_malloc(registry_counter * sizeof(char*));
        if (!keys) {
            LOG_ERR("Failed to allocate memory for keys");
            return -ENOMEM;
        }
        
        char *temp = k_malloc(storage.max_value_len);
        if (!temp) {
            k_free(keys);
            LOG_ERR("Failed to allocate temporary buffer");
            return -ENOMEM;
        }
        
        // Walk the registry
        for (uint16_t i = 0; i < registry_counter; i++) {
            uint16_t key_id = REGISTRY_KEYS_START + i;
            // Copy the keys into the temp buffer
            ret = nvs_read(&storage.nvs, key_id, temp, storage.max_value_len);
            if (ret >= 0 && temp[0] != '\0') { 
                keys[i] = k_malloc(strlen(temp) + 1);
                if (keys[i]) {
                    strcpy(keys[i], temp); // If succesfull write it into keys[i]
                }
            } else {
                keys[i] = NULL;
            }
        }
        
        k_free(temp);
    }
    else{
        ssize_t file_size = fs_manager_get_size("/SD:/settings/.registry.txt");
        if (file_size <= 0) {
            // No registry file yet (or empty)
            return 0;
        }
    
        char *buffer = k_malloc(file_size + 1);
        if (!buffer) return -ENOMEM;
        
        ssize_t len = fs_manager_read_file("/SD:/settings/.registry.txt", buffer, file_size);
        if (len < 0) {
            k_free(buffer);
            return len;
        }
        buffer[len] = '\0';
        
        char *line = buffer;
        while (line && *line) {
            char *next = strchr(line, '\n');
            if (next) {
                registry_counter++;
                line = next + 1;
            } else if (*line) {
                registry_counter++;
                break;
            } else {
                break;
            }
        }
        
        if (registry_counter == 0) {
            k_free(buffer);
            return 0;
        }
        
        keys = k_malloc(registry_counter * sizeof(char*));
        if (!keys) {
            k_free(buffer);
            return -ENOMEM;
        }
        
        line = buffer;
        uint16_t idx = 0;
        while (line && *line && idx < registry_counter) {
            char *next = strchr(line, '\n');
            size_t key_len = next ? (next - line) : strlen(line);
            
            if (key_len > 0) {
                keys[idx] = k_malloc(key_len + 1);
                if (keys[idx]) {
                    strncpy(keys[idx], line, key_len);
                    keys[idx][key_len] = '\0';
                    idx++;
                }
            }
            
            line = next ? (next + 1) : NULL;
        }
        
        k_free(buffer);
    }
    *out_keys = keys;
    *out_count = registry_counter;

    return 0;
}

static int registry_save_keys_sd(char **keys, uint16_t count) {
    if (!keys) return -EINVAL;
    
    // Calculate size needed: sum of all key lengths + newlines
    size_t total_size = 0;
    for (uint16_t i = 0; i < count; i++) {
        if (keys[i]) {
            total_size += strlen(keys[i]) + 1; // +1 for '\n'
        }
    }
    
    if (total_size == 0) {
        // Empty registry, delete file
        return fs_manager_delete_file("/SD:/settings/.registry.txt");
    }
    
    // Allocate buffer for registry content
    char *buffer = k_malloc(total_size + 1);
    if (!buffer) return -ENOMEM;
    
    // Build content
    char *dst = buffer;
    for (uint16_t i = 0; i < count; i++) {
        if (keys[i] && keys[i][0] != '\0') {
            size_t len = strlen(keys[i]);
            memcpy(dst, keys[i], len);
            dst += len;
            *dst++ = '\n';
        }
    }
    *dst = '\0';
    
    // Write to file
    int ret = fs_manager_write_file("/SD:/settings/.registry.txt", buffer, dst - buffer);
    k_free(buffer);
    
    return (ret >= 0) ? 0 : ret;
}

static int registry_get_index(const char* key) {
    if (!key) {
        return -EINVAL;
    }
    
    if (storage.type == AKIRA_SETTINGS_STORAGE_FLASH) {
        char **keys = NULL;
        uint16_t registry_counter;
        int ret = registry_get_all_keys(&keys, &registry_counter);
        if (ret < 0) {
            return -1;
        }
        // Walk the registry until we find a match then return the index
        for (uint16_t i = 0; i < registry_counter; i++) {
            if (!keys[i] || keys[i][0] == '\0') {
                continue;
            }
            
            if (strcmp(keys[i], key) == 0) {
                free_keys_array(keys, registry_counter);
                return i;
            }
        }
        free_keys_array(keys, registry_counter);
    }
    else{
        LOG_INF("registry_get_index(const char* key) isnt meant for SD");
        return -ENOTSUP;
    }
    
    return -1;
}


static int registry_add_key(const char* key) {
    if (!key) {
        return -EINVAL;
    }
    
    int ret;
    if (storage.type == AKIRA_SETTINGS_STORAGE_FLASH) {
        uint16_t registry_counter;
        ret = nvs_read(&storage.nvs, REGISTRY_COUNTER_ID, &registry_counter, sizeof(registry_counter));
        if (ret < 0) {
            LOG_ERR("Failed to read registry in add_key");
            return ret;
        }

        if (registry_counter >= storage.max_keys || registry_counter >= REGISTRY_KEYS_SIZE) {
            LOG_ERR("Registry full: %d/%d keys", registry_counter, storage.max_keys);
            return -ENOSPC;
        }

        // Write the key into the registry at START + counter (first free location)
        uint16_t key_id = REGISTRY_KEYS_START + registry_counter;
        ret = nvs_write(&storage.nvs, key_id, key, strlen(key) + 1);
        if (ret < 0) {
            return ret;
        }
        
        // Increment the counter
        uint16_t new_counter = registry_counter + 1; 
        ret = nvs_write(&storage.nvs, REGISTRY_COUNTER_ID, &new_counter, sizeof(new_counter));
        if (ret < 0) {
            return ret;
        }
        
        LOG_INF("ADDED %s to registry at index %d", key, registry_counter);
    }
    else{
        char **keys = NULL;
        uint16_t count = 0;
        int ret = registry_get_all_keys(&keys, &count);
        if (ret < 0) return ret;
        
        // Check if already exists
        for (uint16_t i = 0; i < count; i++) {
            if (keys[i] && strcmp(keys[i], key) == 0) {
                // Already in registry
                free_keys_array(keys, count);
                return 0;
            }
        }
        
        // Check limit
        if (count >= storage.max_keys) {
            free_keys_array(keys, count);
            LOG_ERR("Registry full: %d/%d keys", count, storage.max_keys);
            return -ENOSPC;
        }
        
        // Add new key
        char **new_keys = k_malloc((count + 1) * sizeof(char*));
        if (!new_keys) {
            free_keys_array(keys, count);
            return -ENOMEM;
        }
        
        for (uint16_t i = 0; i < count; i++) {
            new_keys[i] = keys[i];
        }
        new_keys[count] = k_malloc(strlen(key) + 1);
        if (!new_keys[count]) {
            k_free(new_keys);
            free_keys_array(keys, count);
            return -ENOMEM;
        }
        strcpy(new_keys[count], key);
        
        ret = registry_save_keys_sd(new_keys, count + 1);
        
        if (keys) k_free(keys);
        free_keys_array(new_keys, count + 1);
    }
    return 0;
}

static int registry_delete_key(const char* key) {
    if (!key) {
        return -EINVAL;
    }
    
    int ret;
    if (storage.type == AKIRA_SETTINGS_STORAGE_FLASH) {
        uint16_t registry_counter;
        ret = nvs_read(&storage.nvs, REGISTRY_COUNTER_ID, &registry_counter, sizeof(registry_counter));
        if (ret < 0) {
            LOG_ERR("Failed to read registry in delete key");
            return ret;
        }

        int index = registry_get_index(key);
        if (index < 0) {
            LOG_WRN("Key not found in registry: %s", key);
            return -ENOENT;
        }

        char *temp = k_malloc(storage.max_value_len);
        if (!temp) {
            LOG_ERR("Failed to allocate temporary buffer");
            return -ENOMEM;
        }

        // Compact the array by shifting all subsequent keys down
        for (uint16_t i = index; i < registry_counter - 1; i++) {
            uint16_t src_id = REGISTRY_KEYS_START + i + 1;
            uint16_t dst_id = REGISTRY_KEYS_START + i;
            
            ret = nvs_read(&storage.nvs, src_id, temp, storage.max_value_len);
            if (ret >= 0) {
                ret = nvs_write(&storage.nvs, dst_id, temp, strlen(temp) + 1);
                if (ret < 0) {
                    LOG_ERR("Failed to shift key during deletion");
                    k_free(temp);
                    return ret;
                }
            }
        }

        k_free(temp);

        // Delete the last id since we shifted it
        uint16_t last_id = REGISTRY_KEYS_START + registry_counter - 1;
        ret = nvs_delete(&storage.nvs, last_id);
        if (ret < 0) {
            LOG_WRN("Failed to delete last entry: %d", ret);
        }

        //Decrement the counter
        uint16_t new_counter = registry_counter - 1; 
        ret = nvs_write(&storage.nvs, REGISTRY_COUNTER_ID, &new_counter, sizeof(new_counter));
        if (ret < 0) {
            LOG_ERR("Failed to update registry counter");
            return ret;
        }

        LOG_INF("Removed %s from registry (compacted array)", key);
    }
    else{
        char **keys = NULL;
        uint16_t count = 0;
        int ret = registry_get_all_keys(&keys, &count);
        if (ret < 0) return ret;
        
        // Find and remove key
        bool found = false;
        for (uint16_t i = 0; i < count; i++) {
            if (keys[i] && strcmp(keys[i], key) == 0) {
                k_free(keys[i]);
                // Shift remaining keys
                for (uint16_t j = i; j < count - 1; j++) {
                    keys[j] = keys[j + 1];
                }
                keys[count - 1] = NULL;
                found = true;
                count--;
                break;
            }
        }
        
        if (!found) {
            free_keys_array(keys, count);
            return -ENOENT;
        }
        
        ret = registry_save_keys_sd(keys, count);
        free_keys_array(keys, count);
    }
    return 0;
}

/*----------------------------MIGRATION <TO DO> ---------------------------------------*/

static int migrate_data_to_sd(void){
    if(storage.type == AKIRA_SETTINGS_STORAGE_SD){
        LOG_WRN("Storage type is already SD");
        return -1;
    }
    return 0;
}

static int migrate_data_to_flash(void){
    if(storage.type == AKIRA_SETTINGS_STORAGE_FLASH){
        LOG_WRN("Storage type is already flash");
        return -1;
    }
    return 0;
}

/*----------------------------SD OPERATIONS--------------------------------------------------*/

static int parse_key(const char* full_key, char* namespace, char* key){
    if (!full_key || !namespace || !key) {
        return -EINVAL;
    }

    const char* last = strrchr(full_key, '/');
    if (!last) {
        strcpy(key, full_key);
        namespace[0] = '\0';
        return 0;
    }

    strcpy(key, last + 1);

    size_t ns_len = last - full_key;
    memcpy(namespace, full_key, ns_len);
    namespace[ns_len] = '\0';

    return 0;
}

static int get_namespace_filepath(const char *namespace, char *filepath, size_t max_len) {
    const char *last_slash = strrchr(namespace, '/');
    const char *filename = last_slash ? (last_slash + 1) : namespace;
    
    int ret = snprintf(filepath, max_len, "/SD:/settings/%s/%s.txt", namespace, filename);
    if (ret < 0 || ret >= max_len) {
        return -EINVAL;
    }
    return 0;
}

static int create_namespace_dir(const char *namespace) {
    char* dirpath = k_malloc(storage.max_value_len);
    snprintf(dirpath, storage.max_value_len, "/SD:/settings/%s", namespace);
    
    // Create each directory level
    char *p = dirpath + strlen("/SD:/settings/");
    while ((p = strchr(p, '/')) != NULL) {
        *p = '\0';
        fs_manager_mkdir(dirpath);
        *p = '/';
        p++;
    }
    int ret = fs_manager_mkdir(dirpath);
    k_free(dirpath);
    return ret;
}

/* Escape special characters */
static char *escape_value(const char *value) {
    if (!value) return NULL;
    
    size_t len = strlen(value);
    size_t escaped_len = len * 2 + 1;
    char *escaped = k_malloc(escaped_len);
    if (!escaped) return NULL;
    
    char *dst = escaped;
    for (const char *src = value; *src; src++) {
        if (*src == '\n') {
            *dst++ = '\\';
            *dst++ = 'n';
        } else if (*src == '\r') {
            *dst++ = '\\';
            *dst++ = 'r';
        } else if (*src == '\\') {
            *dst++ = '\\';
            *dst++ = '\\';
        } else {
            *dst++ = *src;
        }
    }
    *dst = '\0';
    return escaped;
}

/* Unescape special characters */
static char *unescape_value(const char *value) {
    if (!value) return NULL;
    
    size_t len = strlen(value);
    char *unescaped = k_malloc(len + 1);
    if (!unescaped) return NULL;
    
    char *dst = unescaped;
    for (const char *src = value; *src; src++) {
        if (*src == '\\' && *(src + 1)) {
            src++;
            if (*src == 'n') *dst++ = '\n';
            else if (*src == 'r') *dst++ = '\r';
            else if (*src == '\\') *dst++ = '\\';
            else *dst++ = *src;
        } else {
            *dst++ = *src;
        }
    }
    *dst = '\0';
    return unescaped;
}

static int sd_get_value(const char *namespace, const char *key, char *value, size_t max_len) {
    char* filepath = k_malloc(storage.max_value_len * sizeof(char));
    if(!filepath){
        return -ENOMEM;
    }

    int ret = get_namespace_filepath(namespace, filepath, storage.max_value_len);
    if (ret < 0){
        k_free(filepath);
        return ret;
    }
    
    // Get actual file size first
    ssize_t file_size = fs_manager_get_size(filepath);
    if (file_size < 0) {
        k_free(filepath);
        return -ENOENT;
    }
    
    // Allocate only what we need (file size + 1 for null terminator)
    char *buffer = k_malloc(file_size + 1);
    if (!buffer){
        k_free(filepath);
        return -ENOMEM;
    } 
    
    // Read file
    ssize_t read_len = fs_manager_read_file(filepath, buffer, file_size);
    if (read_len < 0) {
        k_free(filepath);
        k_free(buffer);
        return read_len;
    }

    k_free(filepath); // Done with filepath
    buffer[read_len] = '\0';
    
    // Allocate search buffer dynamically (key + "-" + null)
    size_t search_len = strlen(key) + 2;
    char* search = k_malloc(search_len);
    if (!search) {
        k_free(buffer);
        return -ENOMEM;
    }
    snprintf(search, search_len, "%s-", key);
    
    char *line = buffer;
    while (line) {
        char *next_line = strchr(line, '\n');
        
        if (strncmp(line, search, strlen(search)) == 0) {
            // Found it! Extract value
            char *val_start = line + strlen(search);
            size_t val_len = next_line ? (next_line - val_start) : strlen(val_start);
            
            if (val_len >= max_len) {
                val_len = max_len - 1;
            }
            
            strncpy(value, val_start, val_len);
            value[val_len] = '\0';
            
            // Unescape special characters
            char *unescaped = unescape_value(value);
            if (unescaped) {
                strncpy(value, unescaped, max_len - 1);
                value[max_len - 1] = '\0';
                k_free(unescaped);
            }
            
            k_free(search);
            k_free(buffer);
            return 0;
        }
        
        line = next_line ? (next_line + 1) : NULL;
    }
    
    k_free(search);
    k_free(buffer);
    return -ENOENT;
}

static int sd_set_value(const char *namespace, const char *key, const char *value, const char *full_key) {
    // Allocate filepath buffer dynamically
    char* filepath = k_malloc(storage.max_value_len * sizeof(char));
    if (!filepath) {
        return -ENOMEM;
    }
    
    int ret = get_namespace_filepath(namespace, filepath, storage.max_value_len);
    if (ret < 0) {
        k_free(filepath);
        return ret;
    }
    
    // Create directory if needed
    create_namespace_dir(namespace);
    
    // Prepare new line: "key-value\n"
    char *escaped = escape_value(value);
    if (!escaped) {
        k_free(filepath);
        return -ENOMEM;
    }
    
    // Allocate new_line dynamically (key + "-" + escaped + "\n" + null)
    size_t new_line_size = strlen(key) + 1 + strlen(escaped) + 2;
    char *new_line = k_malloc(new_line_size);
    if (!new_line) {
        k_free(escaped);
        k_free(filepath);
        return -ENOMEM;
    }
    
    int new_line_len = snprintf(new_line, new_line_size, "%s-%s\n", key, escaped);
    k_free(escaped);
    
    if (new_line_len >= new_line_size) {
        k_free(new_line);
        k_free(filepath);
        return -E2BIG;
    }
    
    // Read existing file (if it exists)
    char *old_content = NULL;
    size_t old_size = 0;
    bool is_new_key = true;
    
    ssize_t file_size = fs_manager_get_size(filepath);
    if (file_size > 0) {
        old_content = k_malloc(file_size + 1);
        if (!old_content) {
            k_free(new_line);
            k_free(filepath);
            return -ENOMEM;
        }
        
        ssize_t read_len = fs_manager_read_file(filepath, old_content, file_size);
        if (read_len > 0) {
            old_content[read_len] = '\0';
            old_size = read_len;
            is_new_key = false;
        } else {
            k_free(old_content);
            old_content = NULL;
        }
    }
    
    k_free(filepath); // Done with filepath for now
    
    // Calculate new content size (worst case: old + new line)
    size_t new_size = old_size + new_line_len + 1;
    char *new_content = k_malloc(new_size);
    if (!new_content) {
        if (old_content) k_free(old_content);
        k_free(new_line);
        return -ENOMEM;
    }
    
    // Build new content
    char *dst = new_content;
    
    // Allocate search buffer dynamically
    size_t search_len = strlen(key) + 2;
    char *search = k_malloc(search_len);
    if (!search) {
        if (old_content) k_free(old_content);
        k_free(new_content);
        k_free(new_line);
        return -ENOMEM;
    }
    snprintf(search, search_len, "%s-", key);
    
    bool found = false;
    
    if (old_content) {
        // Copy old content, replacing matching line
        char *line = old_content;
        while (line && *line) {
            char *next_line = strchr(line, '\n');
            size_t line_len = next_line ? (next_line - line + 1) : strlen(line);
            
            if (!found && strncmp(line, search, strlen(search)) == 0) {
                // Replace this line with new value
                strcpy(dst, new_line);
                dst += new_line_len;
                found = true;
            } else {
                // Keep this line
                memcpy(dst, line, line_len);
                dst += line_len;
            }
            
            line = next_line ? (next_line + 1) : NULL;
        }
    }
    
    // If key wasn't found, append it
    if (!found) {
        strcpy(dst, new_line);
        dst += new_line_len;
    }
    
    k_free(search);
    k_free(new_line);
    
    *dst = '\0';
    size_t final_size = dst - new_content;
    
    // Need to recreate filepath for writing
    filepath = k_malloc(storage.max_value_len * sizeof(char));
    if (!filepath) {
        if (old_content) k_free(old_content);
        k_free(new_content);
        return -ENOMEM;
    }
    
    ret = get_namespace_filepath(namespace, filepath, storage.max_value_len);
    if (ret < 0) {
        k_free(filepath);
        if (old_content) k_free(old_content);
        k_free(new_content);
        return ret;
    }
    
    // Write to file
    ret = fs_manager_write_file(filepath, new_content, final_size);
    
    k_free(filepath);
    if (old_content) k_free(old_content);
    k_free(new_content);
    
    // Update registry if this was a new key
    if (ret >= 0 && is_new_key && !found) {
        registry_add_key(full_key);
    }
    
    return (ret >= 0) ? 0 : ret;
}

static int sd_delete_value(const char *namespace, const char *key, const char *full_key) {
    // Allocate filepath buffer dynamically
    char* filepath = k_malloc(storage.max_value_len * sizeof(char));
    if (!filepath) {
        return -ENOMEM;
    }
    
    int ret = get_namespace_filepath(namespace, filepath, storage.max_value_len);
    if (ret < 0) {
        k_free(filepath);
        return ret;
    }
    
    // Get file size
    ssize_t file_size = fs_manager_get_size(filepath);
    if (file_size < 0) {
        k_free(filepath);
        return -ENOENT;
    }
    
    // Read existing file
    char *old_content = k_malloc(file_size + 1);
    if (!old_content) {
        k_free(filepath);
        return -ENOMEM;
    }
    
    ssize_t read_len = fs_manager_read_file(filepath, old_content, file_size);
    if (read_len < 0) {
        k_free(filepath);
        k_free(old_content);
        return read_len;
    }
    old_content[read_len] = '\0';
    
    // Allocate new buffer (will be smaller after deletion)
    char *new_content = k_malloc(file_size + 1);
    if (!new_content) {
        k_free(filepath);
        k_free(old_content);
        return -ENOMEM;
    }
    
    // Allocate search buffer dynamically
    size_t search_len = strlen(key) + 2;
    char *search = k_malloc(search_len);
    if (!search) {
        k_free(filepath);
        k_free(old_content);
        k_free(new_content);
        return -ENOMEM;
    }
    snprintf(search, search_len, "%s-", key);
    
    char *dst = new_content;
    char *line = old_content;
    bool found = false;
    
    while (line && *line) {
        char *next_line = strchr(line, '\n');
        size_t line_len = next_line ? (next_line - line + 1) : strlen(line);
        
        if (strncmp(line, search, strlen(search)) == 0) {
            // Skip this line (delete it)
            found = true;
        } else {
            // Keep this line
            memcpy(dst, line, line_len);
            dst += line_len;
        }
        
        line = next_line ? (next_line + 1) : NULL;
    }
    
    k_free(search);
    
    if (!found) {
        k_free(filepath);
        k_free(old_content);
        k_free(new_content);
        return -ENOENT;
    }
    
    *dst = '\0';
    size_t new_size = dst - new_content;
    
    // Write back or delete file if empty
    if (new_size > 0) {
        ret = fs_manager_write_file(filepath, new_content, new_size);
    } else {
        // File would be empty, delete it
        ret = fs_manager_delete_file(filepath);
    }
    
    k_free(filepath);
    k_free(old_content);
    k_free(new_content);
    
    // Update registry
    if (ret >= 0) {
        registry_delete_key(full_key);
    }
    
    return (ret >= 0) ? 0 : ret;
}

/*-------------------------INTERNAL API---------------------------------------- */

static int settings_set(const char* key, const char* value){
    int ret = -1;
    if (storage.type == AKIRA_SETTINGS_STORAGE_FLASH) {
        int index = registry_get_index(key);
        
        if (index < 0) {
            ret = registry_add_key(key);
            if (ret < 0) {
                LOG_ERR("Failed to add key to registry: %d", ret);
                return ret;
            }
            index = registry_get_index(key);
        }
        
        uint16_t id = index + REGISTRY_KEYS_START + REGISTRY_KEYS_SIZE; // Write the value at Index + OFFSET (REGISTRY_KEYS_SIZE + REGISTRY_KEYS_START)
        uint16_t len = strlen(value) + 1;
        ssize_t bytes = nvs_write(&storage.nvs, id, value, len);
        if (bytes < 0) {
            ret = bytes;
        } else {
            ret = 0;
        }
    }
    else{
        char *namespace = k_malloc(storage.max_value_len);
        char *local_key = k_malloc(storage.max_value_len);
        
        if (!namespace || !local_key) {
            if (namespace) k_free(namespace);
            if (local_key) k_free(local_key);
            return -ENOMEM;
        }
        
        ret = parse_key(key, namespace, local_key);
        if (ret < 0) {
            k_free(namespace);
            k_free(local_key);
            return ret;
        }
        
        ret = sd_set_value(namespace, local_key, value, key);
        
        k_free(namespace);
        k_free(local_key);
    }
    return ret;
}

static int settings_get(const char* key, char* value, uint16_t max_len){
    int ret = -1;
    
    // Temporary buffer for reading (might be encrypted)
    char *temp_buf = k_malloc(storage.max_value_len);
    if (!temp_buf) {
        return -ENOMEM;
    }
    
    if (storage.type == AKIRA_SETTINGS_STORAGE_FLASH) {
        int index = registry_get_index(key);
        if (index < 0) {
            k_free(temp_buf);
            return -ENOENT;
        }
        
        uint16_t id = index + REGISTRY_KEYS_SIZE + REGISTRY_KEYS_START;
        int bytes = nvs_read(&storage.nvs, id, temp_buf, storage.max_value_len);
        
        if (bytes < 0) {
            k_free(temp_buf);
            return bytes;
        }
        
        temp_buf[MIN(bytes, storage.max_value_len - 1)] = '\0';
    }
    else {
        char *namespace = k_malloc(storage.max_value_len);
        char *local_key = k_malloc(storage.max_value_len);
        
        if (!namespace || !local_key) {
            if (namespace) k_free(namespace);
            if (local_key) k_free(local_key);
            k_free(temp_buf);
            return -ENOMEM;
        }
        
        ret = parse_key(key, namespace, local_key);
        if (ret < 0) {
            k_free(namespace);
            k_free(local_key);
            k_free(temp_buf);
            return ret;
        }
        
        ret = sd_get_value(namespace, local_key, temp_buf, storage.max_value_len);
        
        k_free(namespace);
        k_free(local_key);
        
        if (ret < 0) {
            k_free(temp_buf);
            return ret;
        }
    }
    
#ifdef CONFIG_AKIRA_SETTINGS_ENCRYPTION
    // Check if data is base64-encoded encrypted data (starts with valid base64)
    // Try to decode and check for encryption magic
    if (strlen(temp_buf) > MINIMUM_ENCRYPTED_LEN) {
        uint8_t *decoded = k_malloc(storage.max_value_len);
        if (decoded) {
            size_t decoded_len;
            ret = base64_decode(decoded, storage.max_value_len, &decoded_len, 
                               temp_buf, strlen(temp_buf));
            
            if (ret == 0 && crypto_is_encrypted(decoded, decoded_len)) {
                // Its encrypted! Decrypt it
                ret = crypto_decrypt(decoded, decoded_len, value, max_len);
                k_free(decoded);
                k_free(temp_buf);
                return ret;
            }
            k_free(decoded);
        }
    }
#endif
    
    strncpy(value, temp_buf, max_len - 1);
    value[max_len - 1] = '\0';
    k_free(temp_buf);
    
    return 0;
}

static int settings_delete(const char* key){
    int ret = -1;
    if (storage.type == AKIRA_SETTINGS_STORAGE_FLASH) {
        int index = registry_get_index(key);
        if (index < 0) {
            return -ENOENT;
        }
        
        uint16_t id =  index + REGISTRY_KEYS_START + REGISTRY_KEYS_SIZE;
        ret = nvs_delete(&storage.nvs, id);
        
        if (ret == 0) {
            registry_delete_key(key);
        }
    }
    else{
        char *namespace = k_malloc(storage.max_value_len);
        char *local_key = k_malloc(storage.max_value_len);
        
        if (!namespace || !local_key) {
            if (namespace) k_free(namespace);
            if (local_key) k_free(local_key);
            return -ENOMEM;
        }
        
        ret = parse_key(key, namespace, local_key);
        if (ret < 0) {
            k_free(namespace);
            k_free(local_key);
            return ret;
        }
        
        ret = sd_delete_value(namespace, local_key, key);
        
        k_free(namespace);
        k_free(local_key);
    }
    return ret;
}

static int settings_clear(void){
    int ret = -1;
    if (storage.type == AKIRA_SETTINGS_STORAGE_FLASH) {
        ret = nvs_clear(&storage.nvs);
        if (!ret) {
            // After clearing you have to reinit
            storage.max_value_len = CONFIG_AKIRA_SETTINGS_MAX_VALUE_LEN;
            storage.max_keys = CONFIG_AKIRA_SETTINGS_MAX_KEYS;
            ret = init_flash();
        }
    } else {
        struct fs_dir_t dir;
        fs_dir_t_init(&dir);
        
        if (fs_opendir(&dir, "/SD:/settings") == 0) {
            struct fs_dirent entry;
            while (fs_readdir(&dir, &entry) == 0) {
                if (entry.name[0] == '\0') break;
                
                if (entry.type == FS_DIR_ENTRY_DIR && 
                    strcmp(entry.name, ".") != 0 && strcmp(entry.name, "..") != 0) {
                    char* dirpath = k_malloc(storage.max_value_len);
                    snprintf(dirpath, storage.max_value_len, "/SD:/settings/%s", entry.name);
                    fs_manager_delete_dir(dirpath);
                    k_free(dirpath);
                }
            }
            fs_closedir(&dir);
        }
        
        // Delete registry
        fs_manager_delete_file("/SD:/settings/.registry.txt");
        
        ret = 0;
    }
    return ret;
}

/*----------------------------WORK QUEUE FUNCTIONS--------------------------------------------------*/

static void setting_work_handler(struct k_work *work) {
    struct akira_setting_work *sw = CONTAINER_OF(work, struct akira_setting_work, work);
    int result = -1;
    
    /* Process operation with mutex held */
    k_mutex_lock(&akira_settings_mutex, K_FOREVER);
    switch (sw->type) {
        case AKIRA_SETTINGS_OP_SET:
        {
            if (sw->key && sw->value) {
                result = settings_set(sw->key, sw->value);
            }
            break;
        }   
        case AKIRA_SETTINGS_OP_GET:
        {
            if (sw->key && sw->value) {
                result = settings_get(sw->key, sw->value, sw->max_len);
            }
            break;   
        }
        case AKIRA_SETTINGS_OP_DELETE:
        {
            if (sw->key) {
                result = settings_delete(sw->key);
            }
            break;
        }
        case AKIRA_SETTINGS_OP_CLEAR:
        {    
            result = settings_clear();
            break;
        }
        case AKIRA_SETTINGS_OP_RESIZE:
        {
            uint16_t new_value_len = sw->max_len;
            uint16_t new_keys = (uint16_t)(uintptr_t)sw->user_data;
            result = resize_limits_internal(new_value_len, new_keys);
            break;
        }
        default:
        {
            LOG_WRN("PUSHED UNKNOWN TYPE TO WORKQUEUE (%d)", sw->type);
            break;
        }
    }
    
    k_mutex_unlock(&akira_settings_mutex);
    
    if (sw->callback) {
        sw->callback(result, sw->user_data);
    }

    if (sw->completion_sem) {
        if (sw->result_ptr) {
            *sw->result_ptr = result;
        }
        k_sem_give(sw->completion_sem);
    } 
    
    /* Cleanup */
    if (sw->key) k_free(sw->key);
    
    /* Only free value for SET operations (we allocated it)
       For GET, value points to caller's buffer - don't free! */
    if (sw->type == AKIRA_SETTINGS_OP_SET && sw->value) {
        k_free(sw->value);
    }
    
    k_free(sw);
}

static int submit_settings_work(struct akira_setting_work *work) {
    if (!storage.initialized) {
        k_free(work->key);
        k_free(work->value);
        k_free(work);
        return -EINVAL;
    }
    
    k_work_init(&work->work, setting_work_handler);
    k_work_submit_to_queue(&storage.work_queue, &work->work);
    
    return 0;
}

/*-------------------------PUBLIC API---------------------------------------- */

int akira_settings_init(void) {
    if (storage.initialized) {
        return 0;
    }
    
    int ret = crypto_init();
    if (ret != 0) {
        LOG_ERR("Failed to initialize encryption: %d", ret);
        return ret;
    }

    switch (storage.type) {
        case AKIRA_SETTINGS_STORAGE_FLASH:
            ret = init_flash();
            if (!ret) {
                storage.type = AKIRA_SETTINGS_STORAGE_FLASH;
            }
            break;
            
        case AKIRA_SETTINGS_STORAGE_SD:
            ret = init_sd();
            if (!ret) {
                storage.type = AKIRA_SETTINGS_STORAGE_SD;
            } else {
                LOG_WRN("SD Unavailable, falling back to flash memory.");
                storage.type = AKIRA_SETTINGS_STORAGE_FLASH;
                return akira_settings_init();
            }
            break;
            
        case AKIRA_SETTINGS_STORAGE_AUTO:
            storage.type = AKIRA_SETTINGS_STORAGE_FLASH;
            return akira_settings_init();
            
        default:
            return -EINVAL;
    }

    if (!ret) {
        k_work_queue_init(&storage.work_queue);

        k_work_queue_start(&storage.work_queue,
                       work_stack,
                       K_THREAD_STACK_SIZEOF(work_stack),
                       K_PRIO_PREEMPT(7),
                       NULL);
        
        storage.initialized = true;
        LOG_INF("Storage initialized to %s", (!storage.type) ? "FLASH" : "SD");
    } else {
        LOG_WRN("Storage initialization failed!");
    }
    
    return ret;
}

int akira_settings_set(const char *key, const char *value) {
    if (!key || !value || !storage.initialized) {
        return -EINVAL;
    }
    
    if (strlen(value) >= storage.max_value_len) {
        LOG_ERR("Value too long: %zu >= %d", strlen(value), storage.max_value_len);
        return -E2BIG;
    }

    if (strlen(key) >= storage.max_value_len) {
        LOG_ERR("Key too long: %zu >= %d", strlen(key), storage.max_value_len);
        return -E2BIG;
    }
    
    struct k_sem completion_sem;
    k_sem_init(&completion_sem, 0, 1);

    int result = -1;
    struct akira_setting_work *work = k_malloc(sizeof(struct akira_setting_work));
    if (!work) return -ENOMEM;
    
    work->type = AKIRA_SETTINGS_OP_SET;
    work->key = k_malloc(strlen(key) + 1);
    work->value = k_malloc(strlen(value) + 1);
    work->callback = NULL;
    work->user_data = NULL;
    work->completion_sem = &completion_sem;
    work->result_ptr = &result;
    
    if (!work->key || !work->value) {
        if (work->key) k_free(work->key);
        if (work->value) k_free(work->value);
        k_free(work);
        return -ENOMEM;
    }
    
    strcpy(work->key, key);
    strcpy(work->value, value);
    
    int ret = submit_settings_work(work);
    if (ret != 0) {
        return ret;
    }
    
    /* Wait for completion */
    k_sem_take(&completion_sem, K_FOREVER);
    
    if (result == 0) {
        LOG_INF("Set: %s = %s", key, value);
    }
    return result;
}

int akira_settings_get(const char *key, char *value, uint16_t max_len) {
    if (!key || !value || max_len == 0 || !storage.initialized) {
        return -EINVAL;
    }
    
    if (strlen(key) >= storage.max_value_len) {
        LOG_ERR("Key too long: %zu >= %d", strlen(key), storage.max_value_len);
        return -EINVAL;
    }
    
    struct k_sem completion_sem;
    k_sem_init(&completion_sem, 0, 1);

    int result = -1;
    struct akira_setting_work *work = k_malloc(sizeof(struct akira_setting_work));
    if (!work) return -ENOMEM;
    
    work->type = AKIRA_SETTINGS_OP_GET;
    work->key = k_malloc(strlen(key) + 1);
    work->value = value;
    work->max_len = max_len;
    work->callback = NULL;
    work->user_data = NULL;
    work->completion_sem = &completion_sem;
    work->result_ptr = &result;
    
    if (!work->key) {
        k_free(work);
        return -ENOMEM;
    }
    
    strcpy(work->key, key);
    
    int ret = submit_settings_work(work);
    if (ret != 0) {
        return ret;
    }
    
    /* Wait for completion */
    k_sem_take(&completion_sem, K_FOREVER);
    
    if (result == 0) {
        LOG_INF("GET: %s = %s", key, value);
    }
    return result;
}

int akira_settings_delete(const char *key) {
    if (!key || !storage.initialized) {
        return -EINVAL;
    }

    struct k_sem completion_sem;
    k_sem_init(&completion_sem, 0, 1);

    int result = -1;
    struct akira_setting_work *work = k_malloc(sizeof(struct akira_setting_work));
    if (!work) return -ENOMEM;
    
    work->type = AKIRA_SETTINGS_OP_DELETE;
    work->key = k_malloc(strlen(key) + 1);
    work->value = NULL;
    work->callback = NULL;
    work->user_data = NULL;
    work->completion_sem = &completion_sem;
    work->result_ptr = &result;
    
    if (!work->key) {
        k_free(work);
        return -ENOMEM;
    }
    
    strcpy(work->key, key);
    
    int ret = submit_settings_work(work);
    if (ret != 0) {
        return ret;
    }
    
    /* Wait for completion */
    k_sem_take(&completion_sem, K_FOREVER);
    
    if (result == 0) {
        LOG_INF("Deleted: %s", key);
    }
    return result;
}

int akira_settings_clear(void) {
    if (!storage.initialized) {
        return -EINVAL;
    }

    struct k_sem completion_sem;
    k_sem_init(&completion_sem, 0, 1);

    int result = -1;
    struct akira_setting_work *work = k_malloc(sizeof(struct akira_setting_work));
    if (!work) return -ENOMEM;
    
    work->type = AKIRA_SETTINGS_OP_CLEAR;
    work->key = NULL;
    work->value = NULL;
    work->callback = NULL;
    work->user_data = NULL;
    work->completion_sem = &completion_sem;
    work->result_ptr = &result;
    
    int ret = submit_settings_work(work);
    if (ret != 0) {
        return ret;
    }
    
    /* Wait for completion */
    k_sem_take(&completion_sem, K_FOREVER);
    
    if (result == 0) {
        LOG_INF("Cleared");
    }
    return result;
}

int akira_settings_list(settings_iterator_t *iter) {
    if (!iter || !storage.initialized) {
        return -EINVAL;
    }
    
    // First call - fetch keys
    if (iter->ptr == NULL) {
        char **keys = NULL;
        uint16_t count;
        
        int ret = registry_get_all_keys(&keys, &count);
        if (ret < 0) {
            return ret;
        }
        
        iter_data_t *data = k_malloc(sizeof(iter_data_t));
        if (!data) {
            free_keys_array(keys, count);
            return -ENOMEM;
        }
        
        data->keys = keys;
        data->count = count;
        data->index = 0;
        iter->ptr = data;
    }
    
    iter_data_t *data = (iter_data_t*)iter->ptr;
    
    // Find next valid key
    while (data->index < data->count) {
        char *cur = data->keys[data->index];
        data->index++;
        
        if (!cur || cur[0] == '\0') {
            continue;
        }
        
        strncpy(iter->key, cur, iter->key_buffer_size - 1);
        iter->key[iter->key_buffer_size - 1] = '\0';
        
        akira_settings_get(cur, iter->value, iter->value_buffer_size);
        
        return 0; 
    }
    
    // No more keys - cleanup
    free_keys_array(data->keys, data->count);
    k_free(data);
    iter->ptr = NULL;
    
    return 1;
}

int akira_settings_resize_limits(uint16_t new_max_value_len, uint16_t new_max_keys) {
    if (!storage.initialized) {
        LOG_ERR("Cannot resize - storage not initialized");
        return -EINVAL;
    }

    if (new_max_keys >= REGISTRY_KEYS_SIZE || !new_max_value_len || !new_max_keys) {
        return -EINVAL;
    }

    // Create resize work item
    struct k_sem completion_sem;
    k_sem_init(&completion_sem, 0, 1);
    int result = -1;

    struct akira_setting_work *work = k_malloc(sizeof(struct akira_setting_work));
    if (!work) return -ENOMEM;

    work->type = AKIRA_SETTINGS_OP_RESIZE;  // Add new enum value
    work->key = NULL;
    work->value = NULL;
    work->max_len = new_max_value_len;  // Reuse this field
    work->callback = NULL;
    work->user_data = (void*)(uintptr_t)new_max_keys;  // Pack into pointer
    work->completion_sem = &completion_sem;
    work->result_ptr = &result;

    int ret = submit_settings_work(work);
    if (ret != 0) {
        return ret;
    }

    // Wait for completion
    k_sem_take(&completion_sem, K_FOREVER);
    
    if (result == 0) {
        LOG_INF("Resize completed successfully");
    }
    
    return result;
}

/*-----------------ASYNC FUNCTIONS (DONT WAIT TO TAKE SEMAPHORE, GET CALLBACK) -----------------------*/

int akira_settings_set_async(const char *key, const char *value, settings_wq_callback_t callback, void *user_data){
    if (!key || !value || !storage.initialized) {
        return -EINVAL;
    }
    
    if (strlen(value) >= storage.max_value_len) {
        LOG_ERR("Value too long: %zu >= %d", strlen(value), storage.max_value_len);
        return -E2BIG;
    }

    if (strlen(key) >= storage.max_value_len) {
        LOG_ERR("Key too long: %zu >= %d", strlen(key), storage.max_value_len);
        return -E2BIG;
    }
    
    struct k_sem completion_sem;
    k_sem_init(&completion_sem, 0, 1);

    int result = -1;
    struct akira_setting_work *work = k_malloc(sizeof(struct akira_setting_work));
    if (!work) return -ENOMEM;
    
    work->type = AKIRA_SETTINGS_OP_SET;
    work->key = k_malloc(strlen(key) + 1);
    work->value = k_malloc(strlen(value) + 1);
    work->callback = callback;
    work->user_data = user_data;
    work->completion_sem = NULL;
    work->result_ptr = NULL;
    
    if (!work->key || !work->value) {
        if (work->key) k_free(work->key);
        if (work->value) k_free(work->value);
        k_free(work);
        return -ENOMEM;
    }
    
    strcpy(work->key, key);
    strcpy(work->value, value);
    
    return submit_settings_work(work);
}

int akira_settings_delete_async(const char *key,  settings_wq_callback_t callback, void *user_data){
    if (!key || !storage.initialized) {
        return -EINVAL;
    }

    struct k_sem completion_sem;
    k_sem_init(&completion_sem, 0, 1);

    int result = -1;
    struct akira_setting_work *work = k_malloc(sizeof(struct akira_setting_work));
    if (!work) return -ENOMEM;
    
    work->type = AKIRA_SETTINGS_OP_DELETE;
    work->key = k_malloc(strlen(key) + 1);
    work->value = NULL;
    work->callback = callback;
    work->user_data = user_data;
    work->completion_sem = NULL;
    work->result_ptr = NULL;
    
    if (!work->key) {
        k_free(work);
        return -ENOMEM;
    }
    
    strcpy(work->key, key);
    
    return submit_settings_work(work);
}

/*-----------------ENCRYPTED FUNCTIONS-----------------------*/

int akira_settings_set_encrypted(const char *key, const char *value) {
#ifndef CONFIG_AKIRA_SETTINGS_ENCRYPTION
    LOG_ERR("Encryption not enabled in build!");
    return -ENOTSUP;
#else
    if (!key || !value) {
        return -EINVAL;
    }
    
    // Allocate buffer for encrypted data: [MAGIC][IV][encrypted][TAG]
    size_t encrypted_buf_size = MAGIC_SIZE + IV_SIZE + strlen(value) + TAG_SIZE;
    uint8_t *encrypted_buf = k_malloc(encrypted_buf_size);
    if (!encrypted_buf) {
        LOG_ERR("Failed to allocate encryption buffer");
        return -ENOMEM;
    }
    
    // Encrypt the value
    int encrypted_len = crypto_encrypt(value, encrypted_buf, encrypted_buf_size);
    if (encrypted_len < 0) {
        LOG_ERR("Encryption failed: %d", encrypted_len);
        k_free(encrypted_buf);
        return encrypted_len;
    }
    
    // Convert to base64 for storage (since settings API expects strings)
    size_t b64_len = 4 * ((encrypted_len + 2) / 3) + 1;
    char *b64_value = k_malloc(b64_len);
    if (!b64_value) {
        k_free(encrypted_buf);
        return -ENOMEM;
    }
    
    size_t written;
    int ret = base64_encode(b64_value, b64_len, &written, encrypted_buf, encrypted_len);
    k_free(encrypted_buf);
    
    if (ret != 0) {
        k_free(b64_value);
        return ret;
    }
    
    // Store using normal API
    ret = akira_settings_set(key, b64_value);
    k_free(b64_value);
    
    if (ret == 0) {
        LOG_INF("Set encrypted: %s = [ENCRYPTED]", key);
    }
    
    return ret;
#endif
}

/*-------------------------SHELL API---------------------------------------- */

/**
 * @brief Get value for a given key
 */
static int cmd_settings_get(const struct shell *sh, size_t argc, char **argv) {
    if (argc < 2) {
        shell_error(sh, "Usage: akira_settings get <key>");
        shell_print(sh, "");
        shell_print(sh, "Description:");
        shell_print(sh, "  Retrieves the value associated with a key.");
        shell_print(sh, "  Automatically decrypts encrypted values.");
        shell_print(sh, "");
        shell_print(sh, "Examples:");
        shell_print(sh, "  akira_settings get user/name");
        shell_print(sh, "  akira_settings get config/timeout");
        shell_print(sh, "  akira_settings get device/id");
        shell_print(sh, "  akira_settings get user/password    # Auto-decrypts if encrypted");
        return -EINVAL;
    }
    
    char *value = k_malloc(storage.max_value_len);
    if (!value) {
        shell_error(sh, "Memory allocation failed");
        return -ENOMEM;
    }
    
    int ret = akira_settings_get(argv[1], value, storage.max_value_len);
    
    if (ret == 0) {
        shell_print(sh, "%s = %s", argv[1], value);
    } else if (ret == -ENOENT) {
        shell_error(sh, "Key not found: %s", argv[1]);
    } else {
        shell_error(sh, "Error: %d", ret);
    }
    
    k_free(value);
    return ret;
}

/**
 * @brief Set value for a given key
 */
static int cmd_settings_set(const struct shell *sh, size_t argc, char **argv) {
    if (argc < 3) {
        shell_error(sh, "Usage: akira_settings set [-e] <key> <value>");
        shell_print(sh, "");
        shell_print(sh, "Description:");
        shell_print(sh, "  Stores a key-value pair. Creates the key if it doesn't exist.");
        shell_print(sh, "  Use -e flag to encrypt sensitive data (passwords, tokens, etc.)");
        shell_print(sh, "");
        shell_print(sh, "Options:");
        shell_print(sh, "  -e    Encrypt the value using AES-256-GCM");
        shell_print(sh, "");
        shell_print(sh, "Examples:");
        shell_print(sh, "  akira_settings set user/name \"John Doe\"");
        shell_print(sh, "  akira_settings set config/timeout 30");
        shell_print(sh, "  akira_settings set device/id ABC123");
        shell_print(sh, "  akira_settings set -e user/password \"MySecret123\"");
        shell_print(sh, "  akira_settings set -e api/token \"sk-abc123xyz\"");
        shell_print(sh, "");
        shell_print(sh, "Note:");
        shell_print(sh, "  - Encrypted values are transparently decrypted when retrieved");
        shell_print(sh, "  - Encryption requires CONFIG_AKIRA_SETTINGS_ENCRYPTION=y");
        return -EINVAL;
    }
    
    bool encrypt = false;
    const char *key;
    const char *value;
    
    // Parse arguments
    if (strcmp(argv[1], "-e") == 0) {
        // Encrypted mode: akira_settings set -e key value
        if (argc < 4) {
            shell_error(sh, "Usage: akira_settings set -e <key> <value>");
            return -EINVAL;
        }
        encrypt = true;
        key = argv[2];
        value = argv[3];
    } else {
        // Normal mode: akira_settings set key value
        encrypt = false;
        key = argv[1];
        value = argv[2];
    }
    
    int ret;
    if (encrypt) {
#ifdef CONFIG_AKIRA_SETTINGS_ENCRYPTION
        ret = akira_settings_set_encrypted(key, value);
        if (ret == 0) {
            shell_print(sh, "✅ Set (encrypted) %s = [ENCRYPTED]", key);
        } else {
            shell_error(sh, "Failed to encrypt: %d", ret);
        }
#else
        shell_error(sh, "❌ Encryption not enabled in build!");
        shell_error(sh, "Enable CONFIG_AKIRA_SETTINGS_ENCRYPTION=y to use -e flag");
        ret = -ENOTSUP;
#endif
    } else {
        ret = akira_settings_set(key, value);
        if (ret == 0) {
            shell_print(sh, "✅ Set %s = %s", key, value);
        } else {
            shell_error(sh, "Failed: %d", ret);
        }
    }
    
    return ret;
}

/**
 * @brief List all stored key-value pairs
 */
static int cmd_settings_list(const struct shell *sh, size_t argc, char **argv) {
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);
    
    shell_print(sh, "");
    shell_print(sh, "Description:");
    shell_print(sh, "  Lists all stored key-value pairs.");
    shell_print(sh, "  Encrypted values are automatically decrypted for display.");
    shell_print(sh, "");
    
    char *key_buf = k_malloc(storage.max_value_len);
    char *value_buf = k_malloc(storage.max_value_len);
    
    if (!key_buf || !value_buf) {
        shell_error(sh, "Memory allocation failed");
        if (key_buf) k_free(key_buf);
        if (value_buf) k_free(value_buf);
        return -ENOMEM;
    }
    
    settings_iterator_t iter = {
        .ptr = NULL,
        .key = key_buf,
        .value = value_buf,
        .key_buffer_size = storage.max_value_len,
        .value_buffer_size = storage.max_value_len
    };
    
    int count = 0;
    
    shell_print(sh, "Stored keys and values:");
    shell_print(sh, "───────────────────────────────────────────────────────");
    
    while (akira_settings_list(&iter) == 0) {
        shell_print(sh, "%s = %s", iter.key, iter.value);
        count++;
    }
    
    shell_print(sh, "───────────────────────────────────────────────────────");
    shell_print(sh, "Total: %d keys", count);
    shell_print(sh, "");
    
    k_free(key_buf);
    k_free(value_buf);
    
    return 0;
}

/**
 * @brief Delete a key-value pair
 */
static int cmd_settings_delete(const struct shell *sh, size_t argc, char **argv)
{
    if (argc < 2) {
        shell_error(sh, "Usage: akira_settings delete <key>");
        shell_print(sh, "");
        shell_print(sh, "Description:");
        shell_print(sh, "  Permanently deletes a key-value pair from storage.");
        shell_print(sh, "");
        shell_print(sh, "Examples:");
        shell_print(sh, "  akira_settings delete user/name");
        shell_print(sh, "  akira_settings delete config/timeout");
        shell_print(sh, "  akira_settings delete device/id");
        shell_print(sh, "  akira_settings delete user/password");
        shell_print(sh, "");
        shell_print(sh, "Note: This operation cannot be undone");
        return -EINVAL;
    }
    
    int ret = akira_settings_delete(argv[1]);
    
    if (ret == 0) {
        shell_print(sh, "✅ Deleted %s", argv[1]);
    } else if (ret == -ENOENT) {
        shell_error(sh, "Key not found: %s", argv[1]);
    } else {
        shell_error(sh, "Failed: %d", ret);
    }
    
    return ret;
}

/**
 * @brief Clear all stored data
 */
static int cmd_settings_clear(const struct shell *sh, size_t argc, char **argv)
{
    if (argc < 2 || strcmp(argv[1], "confirm") != 0) {
        shell_error(sh, "Usage: akira_settings clear confirm");
        shell_print(sh, "");
        shell_print(sh, "Description:");
        shell_print(sh, "  Erases ALL stored settings from flash/SD card.");
        shell_print(sh, "  This removes both encrypted and plaintext data.");
        shell_print(sh, "");
        shell_warn(sh, "⚠️  WARNING: This will DELETE ALL stored data!");
        shell_warn(sh, "⚠️  This action CANNOT be undone!");
        shell_warn(sh, "⚠️  All keys, values, and the registry will be erased!");
        shell_print(sh, "");
        shell_print(sh, "To proceed, type:");
        shell_print(sh, "  akira_settings clear confirm");
        shell_print(sh, "");
        return 0;
    }
    
    int ret = akira_settings_clear();
    
    if (ret == 0) {
        shell_print(sh, "✅ All data cleared successfully");
        shell_print(sh, "Storage has been reset to initial state");
    } else {
        shell_error(sh, "❌ Clear failed: %d", ret);
    }
    
    return ret;
}

/**
 * @brief Show storage configuration and statistics
 */
static int cmd_settings_info(const struct shell *sh, size_t argc, char **argv)
{
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);
    
    shell_print(sh, "");
    shell_print(sh, "Description:");
    shell_print(sh, "  Displays current storage configuration and usage statistics.");
    shell_print(sh, "");
    shell_print(sh, "Storage Configuration:");
    shell_print(sh, "───────────────────────────────────────────────────────");
    shell_print(sh, "Storage type:     %s", 
                storage.type == AKIRA_SETTINGS_STORAGE_FLASH ? "Flash (NVS)" : "SD Card");
    shell_print(sh, "Max value length: %d bytes", storage.max_value_len);
    shell_print(sh, "Max keys:         %d", storage.max_keys);
    
#ifdef CONFIG_AKIRA_SETTINGS_ENCRYPTION
    shell_print(sh, "Encryption:       Enabled (AES-256-GCM)");
#else
    shell_print(sh, "Encryption:       Disabled");
#endif
    
    if (storage.type == AKIRA_SETTINGS_STORAGE_FLASH) {
        uint16_t registry_counter;
        int ret = nvs_read(&storage.nvs, REGISTRY_COUNTER_ID, &registry_counter, sizeof(registry_counter));
        
        if (ret >= 0) {
            shell_print(sh, "Current keys:     %d", registry_counter);
            shell_print(sh, "Available slots:  %d", storage.max_keys - registry_counter);
            
            float usage = (float)registry_counter / storage.max_keys * 100.0f;
            shell_print(sh, "Usage:            %.1f%%", usage);
        }
    } else if (storage.type == AKIRA_SETTINGS_STORAGE_SD) {
        char **keys = NULL;
        uint16_t count = 0;
        int ret = registry_get_all_keys(&keys, &count);
        if (ret == 0) {
            shell_print(sh, "Current keys:     %d", count);
            shell_print(sh, "Available slots:  %d", storage.max_keys - count);
            
            float usage = (float)count / storage.max_keys * 100.0f;
            shell_print(sh, "Usage:            %.1f%%", usage);
            free_keys_array(keys, count);
        }
    }
    
    shell_print(sh, "───────────────────────────────────────────────────────");
    shell_print(sh, "");
    
    return 0;
}

/**
 * @brief Show registry contents
 */
static int cmd_settings_registry(const struct shell *sh, size_t argc, char **argv)
{
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);
    
    shell_print(sh, "");
    shell_print(sh, "Description:");
    shell_print(sh, "  Displays all registered keys in storage.");
    shell_print(sh, "  The registry tracks which keys exist in the system.");
    shell_print(sh, "");
    
    char **keys = NULL;
    uint16_t count = 0;
    int ret = registry_get_all_keys(&keys, &count);
    
    if (ret < 0) {
        shell_error(sh, "Failed to load registry: %d", ret);
        return ret;
    }
    
    shell_print(sh, "Registry (all keys):");
    shell_print(sh, "───────────────────────────────────────────────────────");
    
    if (count == 0) {
        shell_print(sh, "(empty - no keys stored)");
    } else {
        for (uint16_t i = 0; i < count; i++) {
            if (keys[i]) {
                shell_print(sh, "[%3d] %s", i + 1, keys[i]);
            }
        }
    }
    
    shell_print(sh, "───────────────────────────────────────────────────────");
    shell_print(sh, "Total: %d keys registered", count);
    shell_print(sh, "");
    
    free_keys_array(keys, count);
    return 0;
}

/**
 * @brief Resize storage limits
 */
static int cmd_settings_resize(const struct shell *sh, size_t argc, char **argv)
{
    if (argc < 2) {
        shell_error(sh, "Usage: akira_settings resize -k <new_max_keys> -v <new_max_value_len>");
        shell_print(sh, "");
        shell_print(sh, "Description:");
        shell_print(sh, "  Changes the storage capacity limits for keys and value sizes.");
        shell_print(sh, "  Note: Limits can only be INCREASED, never decreased.");
        shell_print(sh, "");
        shell_print(sh, "Options:");
        shell_print(sh, "  -k <num>    Set maximum number of keys");
        shell_print(sh, "  -v <bytes>  Set maximum value length in bytes");
        shell_print(sh, "");
        shell_print(sh, "Examples:");
        shell_print(sh, "  akira_settings resize -k 200            # Increase max keys to 200");
        shell_print(sh, "  akira_settings resize -v 512            # Increase max value to 512 bytes");
        shell_print(sh, "  akira_settings resize -k 200 -v 512     # Increase both");
        shell_print(sh, "");
        shell_print(sh, "Restrictions:");
        shell_print(sh, "  - Cannot shrink limits (would corrupt existing data)");
        shell_print(sh, "  - New max_keys must be >= current number of stored keys");
        shell_print(sh, "  - Changes are permanent and stored in flash");
        shell_print(sh, "");
        return -EINVAL;
    }
    
    // Default to current values
    long new_max_value_len = storage.max_value_len;
    long new_max_keys = storage.max_keys;
    bool keys_specified = false;
    bool value_specified = false;
    
    // Parse flags
    for (size_t i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0) {
            if (i + 1 >= argc) {
                shell_error(sh, "Missing value for -k flag");
                return -EINVAL;
            }
            
            char *endptr;
            new_max_keys = strtol(argv[i + 1], &endptr, 10);
            if (*endptr != '\0' || new_max_keys <= 0 || new_max_keys > UINT16_MAX) {
                shell_error(sh, "Invalid max_keys: %s", argv[i + 1]);
                shell_error(sh, "Must be a positive integer <= %d", UINT16_MAX);
                return -EINVAL;
            }
            keys_specified = true;
            i++; // Skip next argument
            
        } else if (strcmp(argv[i], "-v") == 0) {
            if (i + 1 >= argc) {
                shell_error(sh, "Missing value for -v flag");
                return -EINVAL;
            }
            
            char *endptr;
            new_max_value_len = strtol(argv[i + 1], &endptr, 10);
            if (*endptr != '\0' || new_max_value_len <= 0 || new_max_value_len > UINT16_MAX) {
                shell_error(sh, "Invalid max_value_len: %s", argv[i + 1]);
                shell_error(sh, "Must be a positive integer <= %d", UINT16_MAX);
                return -EINVAL;
            }
            value_specified = true;
            i++; // Skip next argument
            
        } else {
            shell_error(sh, "Unknown flag: %s", argv[i]);
            shell_error(sh, "Valid flags: -k (keys), -v (value_len)");
            return -EINVAL;
        }
    }
    
    // Check if at least one parameter was specified
    if (!keys_specified && !value_specified) {
        shell_error(sh, "No parameters specified. Use -k and/or -v flags.");
        return -EINVAL;
    }
    
    // Show current configuration
    shell_print(sh, "");
    shell_print(sh, "Current configuration:");
    shell_print(sh, "  max_value_len: %d bytes", storage.max_value_len);
    shell_print(sh, "  max_keys:      %d", storage.max_keys);
    shell_print(sh, "");
    
    // Show what will change
    shell_print(sh, "New configuration:");
    if (value_specified) {
        long change = new_max_value_len - storage.max_value_len;
        shell_print(sh, "  max_value_len: %ld bytes (%s%ld)", 
                    new_max_value_len, 
                    change >= 0 ? "+" : "",
                    change);
    } else {
        shell_print(sh, "  max_value_len: %d bytes (unchanged)", storage.max_value_len);
    }
    
    if (keys_specified) {
        long change = new_max_keys - storage.max_keys;
        shell_print(sh, "  max_keys:      %ld (%s%ld)", 
                    new_max_keys,
                    change >= 0 ? "+" : "",
                    change);
    } else {
        shell_print(sh, "  max_keys:      %d (unchanged)", storage.max_keys);
    }
    shell_print(sh, "");
    
    // Perform resize
    int ret = akira_settings_resize_limits((uint16_t)new_max_value_len, (uint16_t)new_max_keys);
    
    if (ret == 0) {
        shell_print(sh, "✅ Successfully resized storage limits!");
        shell_print(sh, "New limits are now active and stored in flash.");
        shell_print(sh, "");
    } else if (ret == -EINVAL) {
        shell_error(sh, "❌ Invalid parameters or cannot shrink limits");
        shell_error(sh, "You can only INCREASE limits, not decrease them");
        shell_print(sh, "");
    } else {
        shell_error(sh, "❌ Resize failed with error: %d", ret);
        shell_print(sh, "");
    }
    
    return ret;
}

SHELL_STATIC_SUBCMD_SET_CREATE(settings_cmds,
    SHELL_CMD_ARG(get, NULL, "Get value for a key", cmd_settings_get, 2, 0),
    SHELL_CMD_ARG(set, NULL, "Set value for a key (use -e to encrypt)", cmd_settings_set, 3, 1),
    SHELL_CMD_ARG(list, NULL, "List all key-value pairs", cmd_settings_list, 1, 0),
    SHELL_CMD_ARG(delete, NULL, "Delete a key-value pair", cmd_settings_delete, 2, 0),
    SHELL_CMD_ARG(clear, NULL, "Clear all stored data (requires confirmation)", cmd_settings_clear, 1, 1),
    SHELL_CMD_ARG(info, NULL, "Show storage configuration and statistics", cmd_settings_info, 1, 0),
    SHELL_CMD_ARG(registry, NULL, "Show all registered keys", cmd_settings_registry, 1, 0),
    SHELL_CMD_ARG(resize, NULL, "Resize storage limits", cmd_settings_resize, 2, 4),
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(akira_settings, &settings_cmds, "Akira persistent settings management", NULL);