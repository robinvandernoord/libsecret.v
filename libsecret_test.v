module libsecret

struct Metadata {
	text   string
	number int
}

fn test_basics() {
	// todo: test UUID

	schema := get_schema()

	assert schema.str() != ''
	schema.debug()

	label := 'v-test-label'
	password := 'v-test-password'

	password_obj := schema.store_password(label, password, Metadata{'v-test-text', 42})
	assert password_obj.valid
	assert password_obj.label == label
	assert password_obj.metadata.text == 'v-test-text'
	assert password_obj.metadata.number == 42

	// mut loaded_metadata := Metadata{}
	// loaded_password := schema.load_password(label, mut loaded_metadata) or { 'missing' }
	// assert loaded_password == password
	// assert loaded_metadata.text == 'v-test-text'
	// assert loaded_metadata.number == 42

	// mut lst := []Metadata{}
	// assert schema.list_passwords(mut lst) // success
	// assert lst.len == 1
	// assert lst[0] == loaded_metadata

	// mut empty_metadata := Metadata{}
	// empty_password := schema.load_password('v-test-nonexisting', mut empty_metadata) or {
	// 	'missing'
	// }
	// assert empty_password != password
	// assert empty_password == 'missing'
	// assert empty_metadata.text == ''
	// assert empty_metadata.number == 0

	// assert schema.remove_password(label)
	// assert !schema.remove_password(label)
	// assert schema.load_password(label, mut loaded_metadata) or { '' } == ''

	// lst = []Metadata{}
	// assert !schema.list_passwords(mut lst) // empty
	// assert lst == []
}
