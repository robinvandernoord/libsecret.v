#ifndef V_SUPPORT_H
#define V_SUPPORT_H

#include <libsecret/secret.h>

typedef struct PasswordInfo {
    char* password;
    char* metadata;
} PasswordInfo;

void print_secret_schema(const SecretSchema* schema);
const SecretSchema* get_schema();
int store_password_sync(SecretSchema* schema, char* label, char* password, char* metadata);
PasswordInfo* get_password_sync(SecretSchema* schema, char* label);
int remove_password_sync(SecretSchema* schema, char* label)

char* extract_password(PasswordInfo* info);
char* extract_metadata(PasswordInfo* info);
char* passwordinfo_null(void* _);

#endif // V_SUPPORT_H
