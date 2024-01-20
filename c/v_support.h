#ifndef V_SUPPORT_H
#define V_SUPPORT_H

#include <libsecret/secret.h>

typedef struct PasswordInfo {
    char* password;
    char* metadata;
} PasswordInfo;

void print_secret_schema(const SecretSchema* schema);
const SecretSchema* get_schema();
int store_password_sync(SecretSchema* schema, char* uuid, char* label, char* password, char* metadata);
PasswordInfo* get_password_sync(SecretSchema* schema, char* label);
int remove_password_sync(SecretSchema* schema, char* label)

char* list_passwords(SecretSchema* schema);

char* passwordinfo_uuid(PasswordInfo* info)
char* passwordinfo_password(PasswordInfo* info)
char* passwordinfo_label(PasswordInfo* info)
char* passwordinfo_metadata(PasswordInfo* info)
char* passwordinfo_null(PasswordInfo* info)

_Bool is_null(void* info)

#endif // V_SUPPORT_H
