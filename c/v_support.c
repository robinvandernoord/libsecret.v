#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include <glib.h>
#include <libsecret/secret.h>

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
        "v.robinvandernoord.libsecret",  // you can get a c-string in V with
                                         // c"some contents" but idk how to make
                                         // that const
        SECRET_SCHEMA_NONE,
        {
            {"metadata",
             SECRET_SCHEMA_ATTRIBUTE_STRING},  // more types are supported but
                                               // json dumping into one field is
                                               // easiest
            {"label",
             SECRET_SCHEMA_ATTRIBUTE_STRING},  // also store label because
                                               // otherwise lookup won't work?
            {NULL, 0},
        }};

    // print_secret_schema(&the_schema);
    return &the_schema;
}

// #store-a-password

int store_password_sync(SecretSchema* schema,
                        char* label,
                        char* password,
                        char* metadata) {
    GError* error = NULL;

    /*
     * The variable argument list is the attributes used to later
     * lookup the password. These attributes must conform to the schema.
     */
    secret_password_store_sync(
        schema, SECRET_COLLECTION_DEFAULT, label, password, NULL, &error,
        "label", label,  // save as metadata as well because otherwise we can't
                         // lookup for some reason
        "metadata", metadata, NULL);

    if (error != NULL) {
        /* ... handle the failure here */
        g_error_free(error);
        return 0;
    } else {
        /* ... do something now that the password has been stored */
        return 1;
    }
}

// #lookup-a-password
// char* get_password_sync(SecretSchema* schema, char* label) {
//     GError* error = NULL;

//     /* The attributes used to lookup the password should conform to the
//     schema.
//      */
//     gchar* password = secret_password_lookup_sync(
//         schema, NULL, &error, "label", label, NULL);

//     printf("password: ");
//     printf(password);
//     printf("\n");

//     if (error != NULL) {
//         /* ... handle the failure here */
//         g_error_free(error);
//         return NULL;
//     } else if (password == NULL) {
//         /* password will be null, if no matching password found */
//         return NULL;
//     } else {
//         /* ... do something with the password */
//         return password;
//         // secret_password_free(password);
//     }
// }

char* get_password_sync(SecretSchema* schema, char* label) {
    char* password_str;
    char* metadata_str;

    GError* error = NULL;

    /* The attributes used to lookup the password should conform to the schema.*/
    GList* info = secret_password_search_sync(schema, NULL, NULL, &error,
                                              "label", label, NULL);
    if (error != NULL) {
        /* ... handle the failure here */
        g_error_free(error);
        return NULL;
    } else if (info == NULL) {
        /* info will be null, if no matching entry found */
        return NULL;
    }

    /* ... do something with the info */
    GList* iter;
    for (iter = info; iter != NULL; iter = g_list_next(iter)) {
        SecretRetrievable* password_info = (SecretRetrievable*)iter->data;

        GError* error = NULL;
        SecretValue* secret_value = secret_retrievable_retrieve_secret_sync(password_info, NULL, &error);
        if (error != NULL) {
            continue;
        }

        GHashTable* attrs = secret_retrievable_get_attributes(password_info);

        gpointer metadata = g_hash_table_lookup(attrs, "metadata");

        if (metadata == NULL) {
            metadata_str = "";
        } else {
            metadata_str = strdup(metadata); // copy string
        }

        g_hash_table_unref(attrs); // clean up

        password_str = strdup(secret_value_get_text(secret_value));

        secret_value_unref(secret_value); // clean up

        break; // only do one
    }

    return password_str;
}
