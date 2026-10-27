.PHONY: build
build:
	@./scripts/$@

.PHONY: clean
clean:
	@./scripts/$@

.PHONY: format
format:
	@./scripts/$@

.PHONY: test
test: clean build
	@./scripts/$@

.PHONY: update-fake-leaks
update-fake-leaks:
	@./scripts/$@
