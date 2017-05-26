deps:
	go get -u \
		github.com/jteeuwen/go-bindata \
		github.com/Masterminds/glide
	glide install --strip-vendor

generate:
	go-bindata -pkg=saml -o=bindata_test.go test_data
	go-bindata -pkg=main -o=examples/svcprovider/bindata.go examples/svcprovider/keys examples/svcprovider/pages

test: generate
	go test

build-example:
	mkdir -p build
	go build -i -o build/svcprovider github.com/murphybytes/saml/examples/svcprovider
