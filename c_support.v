module libsecret

// include custom c code:
#flag -I @VMODROOT/c
#flag @VMODROOT/c/v_support.c
// include shared libraries (libsecret-dev + deps)
#flag -I/usr/include/libsecret-1 -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include/
#flag -lglib-2.0 -lsecret-1

struct C.SecretSchema {
    // does have properties but filling them in breaks integration with C
}

fn C.get_schema() &C.SecretSchema
fn C.print_secret_schema(schema &C.SecretSchema)

fn C.store_password_sync(schema &C.SecretSchema, label &u8, password &u8, metadata &u8) int // &u8 = c string