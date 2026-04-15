// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        memset(id_out->hash, 0, HASH_SIZE);
        return;
    }
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // Get type string
    const char *type_str;
    switch (type) {
        case OBJ_BLOB: type_str = "blob"; break;
        case OBJ_TREE: type_str = "tree"; break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }
    
    // Build header
    char header[256];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    
    // Build full object (header + null terminator + data)
    size_t full_len = header_len + 1 + len;
    void *full_obj = malloc(full_len);
    if (!full_obj) return -1;
    memcpy(full_obj, header, header_len);
    ((char*)full_obj)[header_len] = '\0';
    memcpy((char*)full_obj + header_len + 1, data, len);
    
    // Compute hash of full object
    ObjectID id;
    compute_hash(full_obj, full_len, &id);
    
    // Check if object already exists (deduplication)
    if (object_exists(&id)) {
        free(full_obj);
        *id_out = id;
        return 0;
    }
    
    // Create shard directory if needed
    char shard_dir[512];
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&id, hex);
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755);  // OK if it already exists
    
    // Create temp file path
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/.tmp", shard_dir);
    
    // Write to temp file
    int fd = open(temp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full_obj);
        return -1;
    }
    
    if (write(fd, full_obj, full_len) != (ssize_t)full_len) {
        close(fd);
        unlink(temp_path);
        free(full_obj);
        return -1;
    }
    
    // Sync temp file to disk
    if (fsync(fd) != 0) {
        close(fd);
        unlink(temp_path);
        free(full_obj);
        return -1;
    }
    close(fd);
    
    // Get final object path and rename temp to final
    char final_path[512];
    object_path(&id, final_path, sizeof(final_path));
    if (rename(temp_path, final_path) != 0) {
        unlink(temp_path);
        free(full_obj);
        return -1;
    }
    
    // Sync shard directory to persist the rename
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }
    
    free(full_obj);
    *id_out = id;
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // Get object file path
    char path[512];
    object_path(id, path, sizeof(path));
    
    // Open and read file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    
    // Get file size
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (fsize <= 0) {
        fclose(f);
        return -1;
    }
    
    // Read entire file
    void *file_data = malloc(fsize);
    if (!file_data) {
        fclose(f);
        return -1;
    }
    
    if (fread(file_data, 1, fsize, f) != (size_t)fsize) {
        free(file_data);
        fclose(f);
        return -1;
    }
    fclose(f);
    
    // Find null terminator separating header and data
    void *null_pos = memchr(file_data, '\0', fsize);
    if (!null_pos) {
        free(file_data);
        return -1;
    }
    
    size_t header_len = (char*)null_pos - (char*)file_data;
    
    // Parse header
    char header[256];
    if (header_len >= sizeof(header)) {
        free(file_data);
        return -1;
    }
    memcpy(header, file_data, header_len);
    header[header_len] = '\0';
    
    // Parse type and size
    char type_str[32];
    size_t stored_size;
    if (sscanf(header, "%31s %zu", type_str, &stored_size) != 2) {
        free(file_data);
        return -1;
    }
    
    // Verify size
    size_t actual_data_len = fsize - header_len - 1;
    if (actual_data_len != stored_size) {
        free(file_data);
        return -1;
    }
    
    // Verify integrity by recomputing hash
    ObjectID computed_id;
    compute_hash(file_data, fsize, &computed_id);
    if (memcmp(computed_id.hash, id->hash, HASH_SIZE) != 0) {
        free(file_data);
        return -1;  // Corrupt object
    }
    
    // Set type output
    if (strncmp(type_str, "blob", 4) == 0) {
        *type_out = OBJ_BLOB;
    } else if (strncmp(type_str, "tree", 4) == 0) {
        *type_out = OBJ_TREE;
    } else if (strncmp(type_str, "commit", 6) == 0) {
        *type_out = OBJ_COMMIT;
    } else {
        free(file_data);
        return -1;
    }
    
    // Extract and return data
    void *data = malloc(actual_data_len);
    if (!data) {
        free(file_data);
        return -1;
    }
    memcpy(data, (char*)file_data + header_len + 1, actual_data_len);
    free(file_data);
    
    *data_out = data;
    *len_out = actual_data_len;
    return 0;
}
