module libsecret

struct Metadata {
	text   string
	number int
}

fn test_basics() {
	println('pre get schema')
	schema := get_schema(Metadata{})
	println('pre remove all')
	assert schema.remove_all() == 0 // assume no issues
	println('pre count')
	assert schema.count_passwords() == 0 // no issues means no more passwords left

	println('pre debug')
	assert schema.str() != ''
	schema.debug()

	label := 'v-test-label'
	password := 'v-test-password'

	println('pre store')
	mut password_obj := schema.store_password(label, password, Metadata{'v-test-text', 42})
	assert password_obj.valid
	assert password_obj.label == label
	assert password_obj.metadata.text == 'v-test-text'
	assert password_obj.metadata.number == 42
	println('post store')

	println('pre load 1')
	password_obj = schema.load_password(label)
	assert password_obj.valid
	assert password_obj.password == password
	assert password_obj.metadata.text == 'v-test-text'
	assert password_obj.metadata.number == 42
	println('post load 1')

	println('pre list')

	lst := schema.list_passwords()
	assert lst.len == 1
	assert lst[0].metadata == password_obj.metadata
	println('post list')

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
