module libsecret

import json

struct SecretSchema {
	c_schema &C.SecretSchema @[skip] // internal only
}

fn (s SecretSchema) str() string {
	// prevent memory error:
	return 'SecretSchema{}'
}

pub fn (s SecretSchema) debug() {
	C.print_secret_schema(s.c_schema)
}

// only sync methods are currently supported
pub fn (s SecretSchema) store_password[T](label string, password string, metadata T) bool {
	metadata_json := json.encode(metadata)
	success := C.store_password_sync(s.c_schema, label.str, password.str, metadata_json.str)
	return success == 1
}

pub fn (s SecretSchema) load_password[T](label string, mut metadata T) ?string {
	info_obj := C.get_password_sync(s.c_schema, label.str)
	unsafe {
		defer {
			// make sure it's removed from the heap at the end of this function
			// otherwise, calling the same function again might yield old data
			// and it's memory unsafe!
			free(info_obj)
		}
	}
	// first: metadata
	unsafe {
		metadata_raw := C.extract_metadata(info_obj)

		if metadata_raw != nil {
			// got metadata
			metadata_str := metadata_raw.vstring()

			// mut input var:
			metadata = json.decode(T, metadata_str) or { T{} }
		}
	}
	// then: password
	unsafe {
		password_raw := C.extract_password(info_obj)
		if password_raw == nil {
			return none
		}

		return password_raw.vstring()
	}
	return none
}

pub fn get_schema() &SecretSchema {
	// used to get internal C schema struct, which can't be used from V!
	c_schema := C.get_schema()

	return &SecretSchema{c_schema}
}
