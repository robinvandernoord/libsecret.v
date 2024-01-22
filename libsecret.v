module libsecret

import json
import rand

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

struct Password[T] {
pub:
	uuid     string
	label    string
	password string
	metadata &T

	valid bool
}

fn ctov_password[T](c_obj &C.PasswordInfo, meta_type T) &Password[T] {
	unsafe {
		defer {
			// make sure it's removed from the heap at the end of this function
			// otherwise, calling the same function again might yield old data
			// and it's memory unsafe!
			free(c_obj)
		}
	}
	uuid_str := safe_get(c_obj, 'uuid') or { '' }
	label_str := safe_get(c_obj, 'label') or { '' }
	password_str := safe_get(c_obj, 'password') or { '' }

	metadata_str := safe_get(c_obj, 'metadata') or { '' }
	metadata := json.decode(T, metadata_str) or { T{} }

	success := !C.is_null(c_obj) && uuid_str != ''

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
	// todo: if label already exists - update
	// else, create

	uuid := rand.uuid_v4()
	return s.store_password_with_uuid(uuid, label, password, metadata)
}

pub fn (s SecretSchema[T]) load_password_from_uuid[T](uuid string) &Password[T] {
	info_obj := C.get_password_sync(s.c_schema, uuid.str, false)

	return ctov_password(info_obj, s.meta_type)
}

pub fn (s SecretSchema[T]) load_password[T](uuid_or_label string) &Password[T] {
	info_obj := C.get_password_sync(s.c_schema, uuid_or_label.str, true)

	return ctov_password(info_obj, s.meta_type)
}

pub fn (s SecretSchema[T]) remove_password_by_uuid(uuid string) bool {
	return C.remove_password_sync(s.c_schema, uuid.str, false)
}

pub fn (s SecretSchema[T]) remove_password(label_or_uuid string) bool {
	return C.remove_password_sync(s.c_schema, label_or_uuid.str, true)
}

pub fn (s SecretSchema[T]) count_passwords() int {
	return C.count_passwords(s.c_schema)
}

pub fn (s SecretSchema[T]) remove_all() int {
	uuids := s.list_uuids()
	results := uuids.map(s.remove_password_by_uuid(it))
	return results.filter(it != true).len
}

pub fn (s SecretSchema[T]) list_uuids[T]() []string {
	raw := C.list_uuids(s.c_schema)

	mut uuids_str := ''
	unsafe {
		defer {
			free(raw)
		}

		if raw == nil {
			return []
		}
		uuids_str = cstring_to_vstring(raw)
		// uuids_str = raw.vstring()
	}
	return json.decode([]string, uuids_str) or { [] }
}

pub fn (s SecretSchema[T]) list_passwords[T]() []&Password[T] {
	// list UUIDs:
	uuids := s.list_uuids()

	// load PasswordItems from UUIDs:
	// todo: load_password by UUID only, not label too?
	return uuids.map(s.load_password_from_uuid(it))
}

pub fn get_schema[T](meta_type T) &SecretSchema[T] {
	// used to get internal C schema struct, which can't be directly used from V!
	c_schema := C.get_schema()

	return &SecretSchema[T]{c_schema, meta_type}
}
