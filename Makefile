PATTERN_FILES := target/patterns/gitleaks/7.6.1

.PHONY: all
all: $(PATTERN_FILES)

.PHONY: clean
clean:
	rm -rf target

.PHONY: test
test:
	@./scripts/$@

target/patterns/gitleaks/7.6.1: $(wildcard patterns/gitleaks/7.6.1/*)
	mkdir -p target/patterns/gitleaks
	rm -f target/patterns/gitleaks/7.6.1
	for pattern_file in $$(ls patterns/gitleaks/7.6.1/*); do \
		cat $$pattern_file >> $@ && \
		echo >> $@; \
	done
