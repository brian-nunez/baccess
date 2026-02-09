.PHONY: test coverage clean

GO_PACKAGES = ./pkg/predicates ./pkg/auth ./pkg/config

test:
	@echo "Ensuring Go modules are tidy..."
	go mod tidy
	@echo "Running all tests..."
	go test -v $(GO_PACKAGES)

coverage: test
	@echo "Generating coverage report..."
	go test -v -coverprofile=coverage.out $(GO_PACKAGES)
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out | grep total
	@echo "Coverage report generated: coverage.html"

clean:
	@echo "Cleaning up..."
	rm -f coverage.out coverage.html
	go clean -testcache
	@echo "Cleanup complete."
