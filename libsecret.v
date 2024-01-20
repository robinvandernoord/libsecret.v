module libsecret

import json
import rand

struct Password[T] {
	uuid     string
	label    string
	password string
	metadata &T

	valid bool
}

fn ctov_password[T](c_obj &C.PasswordInfo, meta_type T) &Password[T] {
	uuid_str := safe_get(c_obj, 'uuid') or { '' }
	label_str := safe_get(c_obj, 'label') or { '' }
	password_str := safe_get(c_obj, 'password') or { '' }

	metadata_str := safe_get(c_obj, 'metadata') or { '' }
	metadata := json.decode(T, metadata_str) or { T{} }

	success := !C.is_null(c_obj)
	return &Password[T]{uuid_str, label_str, password_str, &metadata, success}
}

struct SecretSchema[T] {
	// internal only:
	c_schema  &C.SecretSchema @[skip]
	meta_type T               @[skip]
}

fn (s SecretSchema[T]) str() string {
	// prevent memory error:
	return 'SecretSchema{}'
}

pub fn (s SecretSchema[T]) debug() {
	C.print_secret_schema(s.c_schema)
}

pub fn (s SecretSchema[T]) store_password_with_uuid[T](uuid string, label string, password string, metadata T) &Password[T] {
	metadata_json := json.encode(metadata)

	// only sync methods are currently supported
	success := C.store_password_sync(s.c_schema, uuid.str, label.str, password.str, metadata_json.str)

	return &Password[T]{uuid, label, password, &metadata, success}
}

pub fn (s SecretSchema[T]) store_password[T](label string, password string, metadata T) &Password[T] {
	uuid := rand.uuid_v4()
	return s.store_password_with_uuid(uuid, label, password, metadata)
}

fn safe_get(info &C.PasswordInfo, field string) ?string {
	data_raw := match field {
		// only needed because info.uuid etc. does not seem to work
		'uuid' { C.passwordinfo_uuid(info) }
		'label' { C.passwordinfo_label(info) }
		'password' { C.passwordinfo_password(info) }
		'metadata' { C.passwordinfo_metadata(info) }
		else { C.passwordinfo_null(info) } // why can't I just panic() here?
	}

	unsafe {
		if data_raw == nil {
			return none
		}
		// got data
		return data_raw.vstring()
	}
}

pub fn (s SecretSchema[T]) load_password[T](uuid_or_label string) &Password[T] {
	info_obj := C.get_password_sync(s.c_schema, uuid_or_label.str)

	unsafe {
		defer {
			// make sure it's removed from the heap at the end of this function
			// otherwise, calling the same function again might yield old data
			// and it's memory unsafe!
			free(info_obj)
		}
	}
	return ctov_password(info_obj, s.meta_type)
}

pub fn (s SecretSchema[T]) remove_password(label_or_uuid string) bool {
	return C.remove_password_sync(s.c_schema, label_or_uuid.str)
}

pub fn (s SecretSchema[T]) list_passwords[T]() []T {
	// todo: return or fill []Password
	raw_result := C.list_passwords(s.c_schema)
	defer {
		unsafe {
			// clean malloc heap obj:
			free(raw_result)
		}
	}

	return []
}

pub fn get_schema[T](meta_type T) &SecretSchema[T] {
	// used to get internal C schema struct, which can't be directly used from V!
	c_schema := C.get_schema()

	return &SecretSchema[T]{c_schema, meta_type}
}
