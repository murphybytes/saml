deps:
	go get -u \
		github.com/jteeuwen/go-bindata \
		github.com/Masterminds/glide
	glide install --strip-vendor

generate:
	go-bindata -pkg=saml -o=bindata_test.go test_data

test: generate
	go test 
