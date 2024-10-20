#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <zip.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>

#define PATH_MAX 4096
#define LINE_MAX 70 // MANIFEST.MF 行的最大长度

// 用于存储 MANIFEST.MF 条目和完整数据块
typedef struct {
    char *name;
    char *digest;
    char *data_block; // 完整的数据块，包括 Name, SHA1-Digest 和结尾的两个换行符
} ManifestEntry;

// 动态数组
typedef struct {
    ManifestEntry *entries;
    size_t count;
    size_t capacity;
} ManifestEntries;

// 初始化动态数组
void init_manifest_entries(ManifestEntries *me) {
    me->count = 0;
    me->capacity = 10;
    me->entries = (ManifestEntry *)malloc(me->capacity * sizeof(ManifestEntry));
    if (!me->entries) {
        fprintf(stderr, "为动态数组分配内存失败\n");
    }
}

// 添加条目到动态数组
int add_manifest_entry(ManifestEntries *me, const char *name, const char *digest, const char *data_block) {
    if (me->count >= me->capacity) {
        me->capacity *= 2;
        ManifestEntry *new_entries = (ManifestEntry *)realloc(me->entries, me->capacity * sizeof(ManifestEntry));
        if (!new_entries) {
            return 0;
        }
        me->entries = new_entries;
    }
    me->entries[me->count].name = strdup(name);
    me->entries[me->count].digest = strdup(digest);
    me->entries[me->count].data_block = strdup(data_block);
    if (!me->entries[me->count].name || !me->entries[me->count].digest || !me->entries[me->count].data_block) {
        return 0;
    }
    me->count += 1;
    return 1;
}

// 释放动态数组
void free_manifest_entries(ManifestEntries *me) {
    for (size_t i = 0; i < me->count; i++) {
        free(me->entries[i].name);
        free(me->entries[i].digest);
        free(me->entries[i].data_block);
    }
    free(me->entries);
}

// 计算 SHA1 摘要并进行 Base64 编码
char* sha1_base64(const unsigned char* data, size_t len) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(data, len, hash);

    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) return NULL;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 不换行
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        BIO_free(b64);
        return NULL;
    }
    bio = BIO_push(b64, bio);

    if (BIO_write(bio, hash, SHA_DIGEST_LENGTH) <= 0) {
        BIO_free_all(bio);
        return NULL;
    }
    if (BIO_flush(bio) != 1) {
        BIO_free_all(bio);
        return NULL;
    }
    BIO_get_mem_ptr(bio, &bptr);
    if (!bptr) {
        BIO_free_all(bio);
        return NULL;
    }

    char* b64text = (char*)malloc(bptr->length + 1);
    if (!b64text) {
        BIO_free_all(bio);
        return NULL;
    }
    memcpy(b64text, bptr->data, bptr->length);
    b64text[bptr->length] = '\0';

    BIO_free_all(bio);

    return b64text;
}

// 从 ZIP 文件中读取文件内容
unsigned char* read_zip_entry(zip_t* apk, const char* name, zip_uint64_t* size) {
    struct zip_stat st;
    zip_stat_init(&st);
    if (zip_stat(apk, name, 0, &st) != 0) {
        return NULL;
    }

    zip_file_t* zf = zip_fopen(apk, name, 0);
    if (!zf) return NULL;

    unsigned char* contents = (unsigned char*)malloc(st.size);
    if (!contents) {
        zip_fclose(zf);
        return NULL;
    }

    zip_int64_t bytes_read = zip_fread(zf, contents, st.size);
    zip_fclose(zf);

    if (bytes_read < 0 || (zip_uint64_t)bytes_read != st.size) {
        free(contents);
        return NULL;
    }

    *size = st.size;
    return contents;
}

// 添加文件到 ZIP
int add_file_to_zip(zip_t *apk, const char *file_path, const char *archive_name) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = (unsigned char *)malloc(file_size);
    if (!buffer) {
        fclose(file);
        return -1;
    }

    size_t read_bytes = fread(buffer, 1, file_size, file);
    fclose(file);

    if (read_bytes != file_size) {
        free(buffer);
        return -1;
    }

    zip_source_t *src = zip_source_buffer(apk, buffer, file_size, 1);
    if (!src) {
        free(buffer);
        return -1;
    }

    if (zip_file_add(apk, archive_name, src, ZIP_FL_OVERWRITE | ZIP_FL_ENC_UTF_8) < 0) {
        zip_source_free(src);
        return -1;
    }

    return 0;
}

// 复制 APK 内容
int copy_apk_contents(zip_t *apk_in, zip_t *apk_out) {
    zip_int64_t num_entries = zip_get_num_entries(apk_in, 0);
    for (zip_int64_t i = 0; i < num_entries; i++) {
        const char *name = zip_get_name(apk_in, i, 0);
        if (!name) continue;

        struct zip_stat st;
        zip_stat_init(&st);
        if (zip_stat(apk_in, name, 0, &st) != 0) continue;

        zip_file_t *zf = zip_fopen(apk_in, name, 0);
        if (!zf) continue;

        unsigned char *buffer = (unsigned char *)malloc(st.size);
        if (!buffer) {
            zip_fclose(zf);
            continue;
        }

        if (zip_fread(zf, buffer, st.size) != st.size) {
            free(buffer);
            zip_fclose(zf);
            continue;
        }
        zip_fclose(zf);

        zip_source_t *src = zip_source_buffer(apk_out, buffer, st.size, 1);
        if (!src) {
            free(buffer);
            continue;
        }

        // 添加文件到输出 APK
        if (zip_file_add(apk_out, name, src, ZIP_FL_OVERWRITE | ZIP_FL_ENC_UTF_8) < 0) {
            zip_source_free(src);
            continue;
        }
    }
    return 1;
}

// 写入带有行长度限制的行，并进行换行
int write_wrapped_line(FILE *f, const char *prefix, const char *content) {
    size_t prefix_len = strlen(prefix);
    size_t content_len = strlen(content);
    size_t total_len = prefix_len + content_len;

    size_t max_content_per_line = LINE_MAX - prefix_len;

    if (max_content_per_line <= 0) {
        return -1;
    }

    size_t written = 0;
    while (written < content_len) {
        size_t to_write = content_len - written;
        if (to_write > max_content_per_line) {
            to_write = max_content_per_line;
        }

        if (written == 0) {
            fwrite(prefix, 1, prefix_len, f);
        } else {
            fwrite(" ", 1, 1, f);
        }

        fwrite(content + written, 1, to_write, f);
        fwrite("\r\n", 1, 2, f);

        written += to_write;
    }

    return 0;
}

// 生成 MANIFEST.MF 并存储条目数据块
int generate_manifest(const char *apk_path, const char *manifest_path, ManifestEntries *me) {
    int err = 0;
    zip_t *apk = zip_open(apk_path, ZIP_RDONLY, &err);
    if (!apk) {
        fprintf(stderr, "无法打开APK文件: %s\n", apk_path);
        return 0;
    }

    zip_int64_t num_entries = zip_get_num_entries(apk, 0);

    FILE *manifest_file = fopen(manifest_path, "wb");
    if (!manifest_file) {
        zip_close(apk);
        fprintf(stderr, "无法创建 MANIFEST.MF 文件: %s\n", manifest_path);
        return 0;
    }

    // 写入文件头部
    fprintf(manifest_file, "Manifest-Version: 1.0\r\n");
    fprintf(manifest_file, "Created-By: 1.0 (Android SignApk)\r\n");
    fprintf(manifest_file, "\r\n");

    for (zip_int64_t i = 0; i < num_entries; i++) {
        const char *name = zip_get_name(apk, i, 0);
        if (!name) continue;

        // 排除目录和 META-INF/ 目录
        size_t name_len = strlen(name);
        if (name_len == 0) continue;
        if (name[name_len - 1] == '/' || strncmp(name, "META-INF/", 9) == 0) continue;

        zip_uint64_t size = 0;
        unsigned char *data = read_zip_entry(apk, name, &size);
        if (!data) continue;

        // 计算 SHA1 摘要
        char *digest = sha1_base64(data, size);
        free(data);
        if (!digest) {
            fprintf(stderr, "无法计算SHA1摘要: %s\n", name);
            continue;
        }

        // 构建完整的数据块
        // Name: [name]\r\nSHA1-Digest: [digest]\r\n\r\n
        size_t data_block_len = strlen("Name: ") + strlen(name) + strlen("\r\nSHA1-Digest: ") + strlen(digest) + strlen("\r\n\r\n") + 1;
        char *data_block = (char *)malloc(data_block_len);
        if (!data_block) {
            fprintf(stderr, "内存分配失败: %s\n", name);
            free(digest);
            continue;
        }
        snprintf(data_block, data_block_len, "Name: %s\r\nSHA1-Digest: %s\r\n\r\n", name, digest);

        // 写入 MANIFEST.MF，处理行长度限制
        if (write_wrapped_line(manifest_file, "Name: ", name) != 0) {
            fprintf(stderr, "无法写入Name: %s\n", name);
            free(digest);
            free(data_block);
            continue;
        }

        if (write_wrapped_line(manifest_file, "SHA1-Digest: ", digest) != 0) {
            fprintf(stderr, "无法写入SHA1-Digest: %s\n", name);
            free(digest);
            free(data_block);
            continue;
        }

        // 写入空行
        fwrite("\r\n", 1, 2, manifest_file);

        // 添加到 ManifestEntries
        if (!add_manifest_entry(me, name, digest, data_block)) {
            fprintf(stderr, "无法添加Manifest条目: %s\n", name);
            free(digest);
            free(data_block);
            continue;
        }

        free(digest);
        free(data_block);
    }

    fclose(manifest_file);
    zip_close(apk);

    return 1;
}

// 生成 CERT.SF
int generate_cert_sf(const char *cert_sf_path, const ManifestEntries *me) {
    // 计算 SHA1-Digest-Manifest
    // MANIFEST.MF 的内容已写入文件，需计算 MANIFEST.MF 中的条目的对应的文件的摘要
    // 为避免不一致，计算摘要时使用内存中的数据块

    // 计算 MANIFEST.MF 的总大小
    size_t total_size = 0;
    for (size_t i = 0; i < me->count; i++) {
        total_size += strlen(me->entries[i].data_block);
    }

    // 添加文件头部: "Manifest-Version: 1.0\r\nCreated-By: 1.0 (Android SignApk)\r\n\r\n"
    total_size += strlen("Manifest-Version: 1.0\r\nCreated-By: 1.0 (Android SignApk)\r\n\r\n");

    unsigned char *manifest_content = (unsigned char *)malloc(total_size);
    if (!manifest_content) {
        fprintf(stderr, "内存分配失败\n");
        return 0;
    }

    // 在内存中构建 MANIFEST.MF 内容
    size_t offset = 0;
    strcpy((char *)(manifest_content + offset), "Manifest-Version: 1.0\r\n");
    offset += strlen("Manifest-Version: 1.0\r\n");
    strcpy((char *)(manifest_content + offset), "Created-By: 1.0 (Android SignApk)\r\n");
    offset += strlen("Created-By: 1.0 (Android SignApk)\r\n");
    strcpy((char *)(manifest_content + offset), "\r\n");
    offset += strlen("\r\n");

    for (size_t i = 0; i < me->count; i++) {
        size_t len = strlen(me->entries[i].data_block);
        memcpy(manifest_content + offset, me->entries[i].data_block, len);
        offset += len;
    }

    // 计算 SHA1-Digest-Manifest
    char *digest_manifest = sha1_base64(manifest_content, total_size);
    free(manifest_content);
    if (!digest_manifest) {
        fprintf(stderr, "无法计算 MANIFEST.MF 的 SHA1 摘要\n");
        return 0;
    }

    // 创建 CERT.SF 内容
    FILE *cert_sf_file = fopen(cert_sf_path, "wb");
    if (!cert_sf_file) {
        free(digest_manifest);
        fprintf(stderr, "无法创建 CERT.SF 文件: %s\n", cert_sf_path);
        return 0;
    }

    // 写入文件头部
    fprintf(cert_sf_file, "Signature-Version: 1.0\r\n");
    fprintf(cert_sf_file, "Created-By: 1.0 (Android SignApk)\r\n");
    fprintf(cert_sf_file, "SHA1-Digest-Manifest: %s\r\n", digest_manifest);
    fprintf(cert_sf_file, "\r\n");

    free(digest_manifest);

    // 解析 ManifestEntries，逐个条目计算摘要并写入 CERT.SF
    for (size_t i = 0; i < me->count; i++) {
        const char *name = me->entries[i].name;
        const char *data_block = me->entries[i].data_block;

        // 计算 SHA1 摘要
        char *entry_digest = sha1_base64((unsigned char*)data_block, strlen(data_block));
        if (!entry_digest) {
            fprintf(stderr, "无法计算 CERT.SF 中 %s 的 SHA1 摘要\n", name);
            continue;
        }

        // 写入 CERT.SF 条目，处理行长度限制
        if (write_wrapped_line(cert_sf_file, "Name: ", name) != 0) {
            fprintf(stderr, "无法在 CERT.SF 中写入Name: %s\n", name);
            free(entry_digest);
            continue;
        }

        if (write_wrapped_line(cert_sf_file, "SHA1-Digest: ", entry_digest) != 0) {
            fprintf(stderr, "无法在 CERT.SF 中写入 %s 的 SHA1-Digest\n", name);
            free(entry_digest);
            continue;
        }

        // 写入空行
        fwrite("\r\n", 1, 2, cert_sf_file);

        free(entry_digest);
    }

    fclose(cert_sf_file);

    return 1;
}

// 生成 CERT.RSA
int generate_cert_rsa(const char *cert_sf_path, const char *private_key_path, const char *certificate_path, const char *cert_rsa_path) {
    // 读取 CERT.SF 内容
    BIO *in_bio = BIO_new_file(cert_sf_path, "rb");
    if (!in_bio) {
        fprintf(stderr, "无法打开 CERT.SF 文件: %s\n", cert_sf_path);
        return 0;
    }

    // 加载私钥（PKCS#8 格式）
    EVP_PKEY *pkey = NULL;
    FILE *pkey_file = fopen(private_key_path, "r");
    if (pkey_file) {
        pkey = PEM_read_PrivateKey(pkey_file, NULL, NULL, NULL);
        fclose(pkey_file);
    }
    if (!pkey) {
        BIO_free(in_bio);
        fprintf(stderr, "无法加载私钥: %s\n", private_key_path);
        return 0;
    }

    // 加载证书
    X509 *cert = NULL;
    FILE *cert_file = fopen(certificate_path, "r");
    if (cert_file) {
        cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
        fclose(cert_file);
    }
    if (!cert) {
        EVP_PKEY_free(pkey);
        BIO_free(in_bio);
        fprintf(stderr, "加载证书失败: %s\n", certificate_path);
        return 0;
    }

    // 创建包含签名证书的证书栈
    STACK_OF(X509) *certs = sk_X509_new_null();
    if (!certs || sk_X509_push(certs, cert) == 0) {
        fprintf(stderr, "无法创建证书栈\n");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free(in_bio);
        if (certs) sk_X509_free(certs);
        return 0;
    }

    // 创建 PKCS7 签名，使用 SHA1，并添加 PKCS7_NOATTR 标志
    PKCS7 *p7 = PKCS7_sign(cert, pkey, certs, in_bio, PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOATTR);
    sk_X509_pop_free(certs, X509_free); // 释放证书栈，但不释放 cert，因为它已被添加到栈中
    if (!p7) {
        unsigned long err_code = ERR_get_error();
        char err_msg[256];
        ERR_error_string_n(err_code, err_msg, sizeof(err_msg));
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free(in_bio);
        fprintf(stderr, "无法创建 PKCS7 结构: %s\n", err_msg);
        return 0;
    }

    // 写入 CERT.RSA 文件
    FILE *cert_rsa_file = fopen(cert_rsa_path, "wb");
    if (!cert_rsa_file) {
        PKCS7_free(p7);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free(in_bio);
        fprintf(stderr, "无法创建 CERT.RSA 文件: %s\n", cert_rsa_path);
        return 0;
    }

    // 以 DER 格式写入 PKCS7 结构
    if (i2d_PKCS7_fp(cert_rsa_file, p7) <= 0) {
        unsigned long err_code = ERR_get_error();
        char err_msg[256];
        ERR_error_string_n(err_code, err_msg, sizeof(err_msg));
        fclose(cert_rsa_file);
        PKCS7_free(p7);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free(in_bio);
        fprintf(stderr, "无法写入 CERT.RSA 文件: %s\n", err_msg);
        return 0;
    }

    fclose(cert_rsa_file);

    PKCS7_free(p7);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(in_bio);

    return 1;
}

// 生成 MANIFEST.MF 的 Lua API
static int l_generate_manifest(lua_State *L) {
    const char *apk_path = luaL_checkstring(L, 1);
    const char *manifest_path = luaL_checkstring(L, 2);

    ManifestEntries me;
    init_manifest_entries(&me);

    if (!generate_manifest(apk_path, manifest_path, &me)) {
        free_manifest_entries(&me);
        lua_pushnil(L);
        lua_pushstring(L, "无法生成 MANIFEST.MF 文件");
        return 2;
    }

    // 将 ManifestEntries 存储在 Lua 注册表中，等会在 generate_cert_sf 中使用
    ManifestEntries *me_ptr = (ManifestEntries *)malloc(sizeof(ManifestEntries));
    if (!me_ptr) {
        free_manifest_entries(&me);
        lua_pushnil(L);
        lua_pushstring(L, "内存分配失败");
        return 2;
    }
    *me_ptr = me;
    lua_pushlightuserdata(L, me_ptr);
    lua_setfield(L, LUA_REGISTRYINDEX, "manifest_entries");

    lua_pushboolean(L, 1);
    return 1;
}

// 生成 CERT.SF 的 Lua API
static int l_generate_cert_sf(lua_State *L) {
    const char *cert_sf_path = luaL_checkstring(L, 1);

    // 获取 ManifestEntries
    lua_getfield(L, LUA_REGISTRYINDEX, "manifest_entries");
    ManifestEntries *me_ptr = (ManifestEntries *)lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (!me_ptr) {
        lua_pushnil(L);
        lua_pushstring(L, "未找到 ManifestEntries");
        return 2;
    }

    if (!generate_cert_sf(cert_sf_path, me_ptr)) {
        free_manifest_entries(me_ptr);
        free(me_ptr);
        lua_pushnil(L);
        lua_pushstring(L, "无法生成 CERT.SF 文件");
        return 2;
    }

    free_manifest_entries(me_ptr);
    free(me_ptr);

    lua_pushboolean(L, 1);
    return 1;
}

// 生成 CERT.RSA 的 Lua API
static int l_generate_cert_rsa(lua_State *L) {
    const char *cert_sf_path = luaL_checkstring(L, 1);
    const char *private_key_path = luaL_checkstring(L, 2);
    const char *certificate_path = luaL_checkstring(L, 3);
    const char *cert_rsa_path = luaL_checkstring(L, 4);

    if (generate_cert_rsa(cert_sf_path, private_key_path, certificate_path, cert_rsa_path)) {
        lua_pushboolean(L, 1);
        return 1;
    } else {
        lua_pushnil(L);
        lua_pushstring(L, "无法生成 CERT.RSA 文件");
        return 2;
    }
}

// 签名 APK 的 Lua API
static int sign_apk(lua_State *L) {
    int n = lua_gettop(L);
    if (n < 3) {
        lua_pushnil(L);
        lua_pushstring(L, "参数不足 需要传入 3 个参数");
        return 2;
    }

    const char *apk_path = luaL_checkstring(L, 1);
    const char *private_key_path = luaL_checkstring(L, 2);
    const char *certificate_path = luaL_checkstring(L, 3);
    const char *output_apk_path = NULL;

    if (n >= 4 && !lua_isnil(L, 4)) {
        output_apk_path = luaL_checkstring(L, 4);
    } else {
        output_apk_path = NULL; // 未提供输出路径
    }

    int err = 0;
    zip_t *apk_out = NULL;

    if (output_apk_path) {
        // 提供了输出路径，需要复制 APK 内容
        zip_t *apk_in = zip_open(apk_path, ZIP_RDONLY, &err);
        if (!apk_in) {
            lua_pushnil(L);
            lua_pushstring(L, "无法打开 APK 文件");
            return 2;
        }

        apk_out = zip_open(output_apk_path, ZIP_TRUNCATE | ZIP_CREATE, &err);
        if (!apk_out) {
            zip_close(apk_in);
            lua_pushnil(L);
            lua_pushstring(L, "无法创建输出 APK 文件");
            return 2;
        }

        // 复制 APK 内容
        if (!copy_apk_contents(apk_in, apk_out)) {
            zip_close(apk_in);
            zip_close(apk_out);
            lua_pushnil(L);
            lua_pushstring(L, "无法复制 APK 内容");
            return 2;
        }

        zip_close(apk_in);
    } else {
        // 未提供输出路径，直接在 APK 中添加签名文件
        apk_out = zip_open(apk_path, ZIP_CREATE, &err);
        if (!apk_out) {
            lua_pushnil(L);
            lua_pushstring(L, "无法打开 APK 文件");
            return 2;
        }
    }

    // 创建临时目录用于存放签名文件
    char temp_dir_template[] = "/sdcard/apk_sign_XXXXXX";
    char *temp_dir = mkdtemp(temp_dir_template);
    if (!temp_dir) {
        zip_close(apk_out);
        lua_pushnil(L);
        lua_pushstring(L, "无法创建临时目录");
        return 2;
    }

    // 定义签名文件路径
    char manifest_path[PATH_MAX];
    char cert_sf_path[PATH_MAX];
    char cert_rsa_path[PATH_MAX];

    snprintf(manifest_path, PATH_MAX, "%s/MANIFEST.MF", temp_dir);
    snprintf(cert_sf_path, PATH_MAX, "%s/CERT.SF", temp_dir);
    snprintf(cert_rsa_path, PATH_MAX, "%s/CERT.RSA", temp_dir);

    // 生成签名文件并存储摘要
    ManifestEntries me;
    init_manifest_entries(&me);
    if (!generate_manifest(apk_path, manifest_path, &me)) {
        zip_close(apk_out);
        free_manifest_entries(&me);
        lua_pushnil(L);
        lua_pushstring(L, "无法生成 MANIFEST.MF 文件");
        return 2;
    }

    if (!generate_cert_sf(cert_sf_path, &me)) {
        zip_close(apk_out);
        free_manifest_entries(&me);
        lua_pushnil(L);
        lua_pushstring(L, "无法生成 CERT.SF 文件");
        return 2;
    }

    if (!generate_cert_rsa(cert_sf_path, private_key_path, certificate_path, cert_rsa_path)) {
        zip_close(apk_out);
        lua_pushnil(L);
        lua_pushstring(L, "无法生成 CERT.RSA 文件");
        return 2;
    }

    // 将签名文件添加到 APK 的 META-INF 目录
    zip_int64_t idx = zip_name_locate(apk_out, "META-INF/", 0);
    if (idx == -1) {
        if (zip_dir_add(apk_out, "META-INF/", ZIP_FL_ENC_UTF_8) < 0) {
            zip_close(apk_out);
            lua_pushnil(L);
            lua_pushstring(L, "无法将 META-INF 目录添加到 APK 中");
            return 2;
        }
    }

    // 添加 MANIFEST.MF
    if (add_file_to_zip(apk_out, manifest_path, "META-INF/MANIFEST.MF") != 0) {
        zip_close(apk_out);
        lua_pushnil(L);
        lua_pushstring(L, "无法将 MANIFEST.MF 文件添加到 APK 中");
        return 2;
    }

    // 添加 CERT.SF
    if (add_file_to_zip(apk_out, cert_sf_path, "META-INF/CERT.SF") != 0) {
        zip_close(apk_out);
        lua_pushnil(L);
        lua_pushstring(L, "无法将 CERT.SF 文件添加到 APK 中");
        return 2;
    }

    // 添加 CERT.RSA
    if (add_file_to_zip(apk_out, cert_rsa_path, "META-INF/CERT.RSA") != 0) {
        zip_close(apk_out);
        lua_pushnil(L);
        lua_pushstring(L, "无法将 CERT.RSA 文件添加到 APK 中");
        return 2;
    }

    // 关闭 APK
    if (zip_close(apk_out) != 0) {
        lua_pushnil(L);
        lua_pushstring(L, "无法写入 APK 文件");
        return 2;
    }

    // 删除临时目录和文件
    remove(manifest_path);
    remove(cert_sf_path);
    remove(cert_rsa_path);
    rmdir(temp_dir);

    lua_pushboolean(L, 1);
    return 1;
}

// 将 .pk8 文件转换为 .pem 文件的 Lua API
static int convert_pk8_to_pem(lua_State *L) {
    const char *pk8_path = luaL_checkstring(L, 1);
    const char *pem_path = luaL_checkstring(L, 2);

    // 打开 .pk8 文件（DER 格式的 PKCS#8 私钥）
    FILE *pk8_file = fopen(pk8_path, "rb");
    if (!pk8_file) {
        lua_pushnil(L);
        lua_pushfstring(L, "无法打开 .pk8 文件: %s", pk8_path);
        return 2;
    }

    // 读取文件内容
    fseek(pk8_file, 0, SEEK_END);
    long pk8_size = ftell(pk8_file);
    fseek(pk8_file, 0, SEEK_SET);

    unsigned char *pk8_data = (unsigned char *)malloc(pk8_size);
    if (!pk8_data) {
        fclose(pk8_file);
        lua_pushnil(L);
        lua_pushstring(L, "内存分配失败");
        return 2;
    }

    if (fread(pk8_data, 1, pk8_size, pk8_file) != pk8_size) {
        fclose(pk8_file);
        free(pk8_data);
        lua_pushnil(L);
        lua_pushstring(L, "无法读取 .pk8 文件");
        return 2;
    }
    fclose(pk8_file);

    // 解析 DER 格式的 PKCS#8 私钥
    const unsigned char *p = pk8_data;
    EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, pk8_size);
    if (!pkey) {
        free(pk8_data);
        lua_pushnil(L);
        lua_pushstring(L, "无法解析 .pk8 私钥");
        return 2;
    }

    free(pk8_data);

    // 将私钥以 PEM 格式写入文件
    FILE *pem_file = fopen(pem_path, "w");
    if (!pem_file) {
        EVP_PKEY_free(pkey);
        lua_pushnil(L);
        lua_pushfstring(L, "无法创建 .pem 文件: %s", pem_path);
        return 2;
    }

    if (!PEM_write_PrivateKey(pem_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        EVP_PKEY_free(pkey);
        fclose(pem_file);
        lua_pushnil(L);
        lua_pushstring(L, "无法将私钥写入到 .pem 文件");
        return 2;
    }

    EVP_PKEY_free(pkey);
    fclose(pem_file);

    lua_pushboolean(L, 1);
    return 1;
}

static const struct luaL_Reg apk_sign_lib[] = {
    {"generate_manifest", l_generate_manifest},
    {"generate_cert_sf", l_generate_cert_sf},
    {"generate_cert_rsa", l_generate_cert_rsa},
    {"convert_pk8_to_pem", convert_pk8_to_pem},
    {"sign_apk", sign_apk},
    {NULL, NULL}
};

int luaopen_LuaApkSigner(lua_State *L) {
    luaL_newlib(L, apk_sign_lib);
    return 1;
}



