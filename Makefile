PATTERN_FILES := target/gitleaks/7.6.1/all.toml

.PHONY: all
all: $(PATTERN_FILES)

.PHONY: clean
clean:
	rm -rf target

.PHONY: test
test:
	@./scripts/$@

target/gitleaks/7.6.1/all.toml: $(wildcard patterns/gitleaks/7.6.1/*)
	rm -rf target/gitleaks/7.6.1/
	mkdir -p target/gitleaks/7.6.1/
	for pattern_file in $$(ls patterns/gitleaks/7.6.1/*); do \
		cat $$pattern_file >> $@ && \
		echo >> $@; \
	done
