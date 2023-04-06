.PHONY: all
all: build

.PHONY: clean
clean:
	rm -rf target

format:
	black . $$(grep -Rl '#!.*python' scripts)

.PHONY: build
build:
	@./scripts/$@
