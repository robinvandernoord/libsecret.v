module libsecret

import json

fn safe_get(info &C.PasswordInfo, field string) ?string {
	data_raw := match field {
		// only needed because info.password etc. does not seem to work
		'password' { C.extract_password(info) }
		'metadata' { C.extract_metadata(info) }
		else { C.passwordinfo_null(info) } // why can't I just panic() here?
	}

	unsafe {
		defer {
			free(data_raw)
		}

		if data_raw == nil {
			return none
		}

		// got data
		return cstring_to_vstring(data_raw) // NOTE: cstring_to_vstring should make a copy whereas .vstring() is only a reference - this breaking if the original element is freed!
		// return data_raw.vstring()
	}
}

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
	return C.store_password_sync(s.c_schema, label.str, password.str, metadata_json.str)
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
	metadata_str := safe_get(info_obj, 'metadata') or { '' }
	metadata = json.decode(T, metadata_str) or { T{} }

	// then: password
	return safe_get(info_obj, 'password')
}

pub fn (s SecretSchema) remove_password(label string) bool {
	return C.remove_password_sync(s.c_schema, label.str)
}

pub fn get_schema() &SecretSchema {
	// used to get internal C schema struct, which can't be used from V!
	c_schema := C.get_schema()

	return &SecretSchema{c_schema}
}
