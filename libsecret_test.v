module libsecret

struct Metadata {
	text   string
	number int
}

fn test_basics() {
	schema := get_schema()

	assert schema.str() != ''
	schema.debug()

	label := 'v-test-label'
	password := 'v-test-password'

	assert schema.store_password(label, password, Metadata{'v-test-text', 42})

	mut loaded_metadata := Metadata{}
	loaded_password := schema.load_password(label, mut loaded_metadata) or { 'missing' }
	assert loaded_password == password
	assert loaded_metadata.text == 'v-test-text'
	assert loaded_metadata.number == 42

	mut empty_metadata := Metadata{}
	empty_password := schema.load_password('v-test-nonexisting', mut empty_metadata) or {
		'missing'
	}
	assert empty_password != password
	assert empty_password == 'missing'
	assert empty_metadata.text == ''
	assert empty_metadata.number == 0
}
