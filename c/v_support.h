#ifndef V_SUPPORT_H
#define V_SUPPORT_H

#include <libsecret/secret.h>

void print_secret_schema(const SecretSchema* schema);
const SecretSchema* get_schema();
int store_password_sync(SecretSchema* schema, char* label, char* password, char* metadata);
char* get_password_sync(SecretSchema* schema, char* label);

#endif // V_SUPPORT_H
