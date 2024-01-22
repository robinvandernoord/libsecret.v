#ifndef V_SUPPORT_H
#define V_SUPPORT_H

#include <libsecret/secret.h>

typedef struct PasswordInfo {
    char* uuid;
    char* label;
    char* password;
    char* metadata;
} PasswordInfo;

char* passwordinfo_uuid(PasswordInfo* info)
char* passwordinfo_password(PasswordInfo* info)
char* passwordinfo_label(PasswordInfo* info)
char* passwordinfo_metadata(PasswordInfo* info)
char* passwordinfo_null(PasswordInfo* info)

_Bool is_null(void* info)

void print_secret_schema(const SecretSchema* schema);
const SecretSchema* get_schema();
int store_password_sync(SecretSchema* schema, char* uuid, char* label, char* password, char* metadata);
PasswordInfo* get_password_sync(SecretSchema* schema, char* label_or_uuid, _Bool allow_label);
int remove_password_sync(SecretSchema* schema, char* label_or_uuid, _Bool allow_label)

char* list_uuids(SecretSchema* schema);
int count_passwords(SecretSchema* schema);
// PasswordInfo** list_passwords(SecretSchema* schema);
// PasswordInfo* get_passwordinfo_from_list(PasswordInfo** password_list, int idx);

#endif // V_SUPPORT_H
