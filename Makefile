deps:
	go get -u \
		github.com/jteeuwen/go-bindata \
		github.com/Masterminds/glide
	glide install --strip-vendor

generate:
	rm -f generated/bindata.go
	rm -f examples/svcprovider/generated/bindata.go
	go-bindata -pkg=generated -o=generated/bindata.go test_data
	go-bindata -pkg=generated -o=examples/svcprovider/generated/bindata.go examples/svcprovider/keys examples/svcprovider/pages

test: generate
	go test

build-example: deps generate
	mkdir -p build
	go build -i -o build/svcprovider github.com/murphybytes/saml/examples/svcprovider
