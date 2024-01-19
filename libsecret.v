module libsecret

import json
import rand

struct SecretSchema {
	c_schema &C.SecretSchema @[skip] // internal only
}

struct Password[T] {
	// todo: use this struct
	uuid string
	password ?string
	metadata &T
}

fn (s SecretSchema) str() string {
	// prevent memory error:
	return 'SecretSchema{}'
}

pub fn (s SecretSchema) debug() {
	C.print_secret_schema(s.c_schema)
}

// only sync methods are currently supported
pub fn (s SecretSchema) store_password_with_uuid[T](uuid string, label string, password string, metadata T) bool {
	metadata_json := json.encode(metadata)
	return C.store_password_sync(s.c_schema, uuid.str, label.str, password.str, metadata_json.str)
}

pub fn (s SecretSchema) store_password[T](label string, password string, metadata T) ?string {
	uuid := rand.uuid_v4()
	if(s.store_password_with_uuid(uuid, label, password, metadata)){
		return uuid
	} else {
		return none
	}
}

// fn (s SecretSchema) handle_password_result[T](info_obj C.PasswordInfo, mut metadata T) ?string {}

pub fn (s SecretSchema) load_password[T](uuid_or_label string, mut metadata T) ?string {
	info_obj := C.get_password_sync(s.c_schema, uuid_or_label.str)
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

pub fn (s SecretSchema) remove_password(label_or_uuid string) bool {
	return C.remove_password_sync(s.c_schema, label_or_uuid.str)
}

/**
*/
pub fn (s SecretSchema) list_passwords[T](mut metadata []T) bool {
	// todo: return or fill []Password
	raw_result := C.list_passwords(s.c_schema)
	defer {
		unsafe {
			// clean malloc heap obj:
			free(raw_result)
		}
	}

	unsafe {
		if raw_result == nil {
			return false
		}
		str_result := raw_result.vstring()

		metadata = json.decode([]T, str_result) or { []T{} }

		return true
	}
}

pub fn get_schema() &SecretSchema {
	// used to get internal C schema struct, which can't be directly used from V!
	c_schema := C.get_schema()

	return &SecretSchema{c_schema}
}
