#include <stdio.h>
#include <stdlib.h>
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
            {NULL, 0},
        }};

    // print_secret_schema(&the_schema);
    return &the_schema;
}

// #store-a-password

int store_password_sync(SecretSchema* schema, char* label, char* password, char* metadata) {
    GError* error = NULL;

    /*
     * The variable argument list is the attributes used to later
     * lookup the password. These attributes must conform to the schema.
     */
    secret_password_store_sync(
        schema, SECRET_COLLECTION_DEFAULT, 
        label, password,      NULL, 
        &error, 
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
