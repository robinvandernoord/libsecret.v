module libsecret

import json

struct SecretSchema {
	c_schema &C.SecretSchema @[skip] // internal only
	// t_metadata T
}

fn (s SecretSchema) str() string {
	// prevent memory error:
	return "SecretSchema{}"
}

pub fn (s SecretSchema) debug() {
	C.print_secret_schema(s.c_schema)
}

// only sync methods are currently supported
pub fn (s SecretSchema) store_password_sync[T](label string, password string, metadata T) bool {
	metadata_json := json.encode(metadata)
	success := C.store_password_sync(s.c_schema, label.str, password.str, metadata_json.str)
	return success == 1
}

pub fn get_schema() &SecretSchema {
	// used to get internal C schema struct, which can't be used from V!
	c_schema := C.get_schema()

	return &SecretSchema {
		c_schema
	}
}
