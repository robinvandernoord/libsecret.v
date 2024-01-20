#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include <glib.h>
#include <libsecret/secret.h>

#define APPLICATION "v.robinvandernoord.libsecret"

void print_secret_schema(const SecretSchema* schema) {
    // debug only
    printf("Secret Schema:\n");
    printf("  Name: %s\n", schema->name);
    printf("  Flags: %d\n", schema->flags);

    printf("  Attributes:\n");
    for (int i = 0; schema->attributes[i].name != NULL; ++i) {
        printf("    Attribute %d:\n", i + 1);
        printf("      Name: %s\n", schema->attributes[i].name);
        printf("      Type: %d\n", schema->attributes[i].type);
    }
}

// slightly modified examples from
// https://gnome.pages.gitlab.gnome.org/libsecret/libsecret-c-examples.html

// #define-a-password-schema
const SecretSchema* get_schema() {
    static const SecretSchema the_schema = {
        APPLICATION,  // you can get a c-string in V with
                      // c"some contents" but idk how to make
                      // that const
        SECRET_SCHEMA_NONE,
        {
            {"uuid", SECRET_SCHEMA_ATTRIBUTE_STRING},         // unique idenifyer
            {"metadata", SECRET_SCHEMA_ATTRIBUTE_STRING},     // more types are supported but
                                                              // json dumping into one field is
                                                              // easiest
            {"label", SECRET_SCHEMA_ATTRIBUTE_STRING},        // also store label because
                                                              // otherwise lookup won't work?
            {"application", SECRET_SCHEMA_ATTRIBUTE_STRING},  // and store APPLICATION global for easy listing
            {NULL, 0},
        }};

    // print_secret_schema(&the_schema);
    return &the_schema;
}

// #store-a-password

int store_password_sync(SecretSchema* schema, char* uuid, char* label, char* password, char* metadata) {
    GError* error = NULL;

    /*
     * The variable argument list is the attributes used to later
     * lookup the password. These attributes must conform to the schema.
     */
    secret_password_store_sync(schema, SECRET_COLLECTION_DEFAULT, label, password, NULL, &error, "application",
                               APPLICATION, "uuid", uuid, "label", label,  // save as metadata as well because otherwise
                                                                           // we can't lookup for some reason
                               "metadata", metadata, NULL);

    if (error != NULL) {
        /* ... handle the failure here */
        fprintf(stderr, "Error storing password: %s\n", error->message);
        g_error_free(error);
        return 0;
    } else {
        /* ... do something now that the password has been stored */
        return 1;
    }
}

typedef struct PasswordInfo {
    char* uuid;
    char* label;
    char* password;
    char* metadata;
} PasswordInfo;

_Bool is_null(void* info) {
    return info == NULL;
}

char* passwordinfo_uuid(PasswordInfo* info) {
    return info->uuid;
}

char* passwordinfo_password(PasswordInfo* info) {
    return info->password;
}

char* passwordinfo_label(PasswordInfo* info) {
    return info->label;
}

char* passwordinfo_metadata(PasswordInfo* info) {
    return info->metadata;
}

char* passwordinfo_null(PasswordInfo* info) {
    return NULL;
}

char* get_metadata(SecretRetrievable* password_info) {
    char* result_metadata = "";
    GHashTable* attrs = secret_retrievable_get_attributes(password_info);

    gpointer metadata = g_hash_table_lookup(attrs, "metadata");

    if (metadata != NULL) {
        result_metadata = strdup(metadata);  // copy string
    }

    g_hash_table_unref(attrs);  // clean up

    return result_metadata;
}

char* get_password(SecretRetrievable* password_info) {
    GError* error = NULL;
    SecretValue* secret_value = secret_retrievable_retrieve_secret_sync(password_info, NULL, &error);
    if (error != NULL) {
        g_error_free(error);
        return NULL;
    }
    char* result_password = strdup(secret_value_get_text(secret_value));

    secret_value_unref(secret_value);  // clean up
    return result_password;
}

PasswordInfo* get_password_sync(SecretSchema* schema, char* label_or_uuid) {
    // throw it on the heap:
    PasswordInfo* result = (PasswordInfo*)malloc(sizeof(PasswordInfo));

    result->uuid     = NULL;
    result->label    = NULL;
    result->password = NULL;
    result->metadata = NULL;

    GError* error = NULL;

    /* The attributes used to lookup the password should conform to the
     * schema.*/
    GList* info = secret_password_search_sync(schema, SECRET_SEARCH_NONE, NULL, &error, "application", APPLICATION,
                                              "label", label_or_uuid, NULL);

    // todo: first get by uuid, then by label

    if (error != NULL) {
        /* ... handle the failure here */
        fprintf(stderr, "Error loading password: %s\n", error->message);
        g_error_free(error);
        return result;
    } else if (info == NULL) {
        /* info will be null, if no matching entry found */
        return result;
    }

    /* ... do something with the info */
    GList* iter;
    for (iter = info; iter != NULL; iter = g_list_next(iter)) {
        SecretRetrievable* password_info = (SecretRetrievable*)iter->data;

        result->password = get_password(password_info);
        result->metadata = get_metadata(password_info);

        break;  // only do one
    }

    g_list_free_full(info, g_object_unref);

    return result;
}

// #remove-a-password
int remove_password_sync(SecretSchema* schema, char* uuid_or_label) {
    GError* error = NULL;

    /*
     * The variable argument list is the attributes used to later
     * lookup the password. These attributes must conform to the schema.
     */
    gboolean removed =
        secret_password_clear_sync(schema, NULL, &error, "application", APPLICATION, "label", uuid_or_label, NULL);

    // todo: support uuid

    if (error != NULL) {
        /* ... handle the failure here */
        fprintf(stderr, "Error removing password: %s\n", error->message);
        g_error_free(error);
        return 0;
    } else {
        /* removed will be TRUE if a password was removed */
        return removed;
    }
}

GList* list_all(SecretSchema* schema) {
    GError* error = NULL;

    GList* info = secret_password_search_sync(schema, SECRET_SEARCH_ALL, NULL, &error, NULL);
    if (error != NULL) {
        return NULL;
    }
    return info;
}

// todo: remove_all ?

char* list_passwords(SecretSchema* schema) {
    // fixme: only returns []Metadata now,
    // no identifying labels...

    GList* info = list_all(schema);
    if (info == NULL) {
        return NULL;
    }

    int items = g_list_length(info);
    int idx = 0;

    char* result = (char*)malloc(2);  // 2 for [ and ]
    strcpy(result, "[");

    GList* iter;
    for (iter = info; iter != NULL; iter = g_list_next(iter)) {
        SecretRetrievable* password_info = (SecretRetrievable*)iter->data;

        // char* label = password_info.get_label();

        char* metadata = get_metadata(password_info);

        // "label": metadata,

        size_t current_length = strlen(result);
        size_t new_length = current_length + strlen(metadata) + 1;  // +1 for comma

        result = (char*)realloc(result, new_length);
        strcat(result, strdup(metadata));

        free(metadata);
        // if not last one:
        idx++;

        if (idx != items) {
            strcat(result, ",");
        }
    }
    g_list_free_full(info, g_object_unref);

    strcat(result, "]");

    // free(result); // defered in V
    return result;
}
