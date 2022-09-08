PATTERN_FILES := target/patterns/gitleaks/7.6.1
PATTERN_FILES += target/patterns/gitleaks/8.12.0

.PHONY: all
all: $(PATTERN_FILES)

.PHONY: clean
clean:
	rm -rf target

.PHONY: test
test:
	@./scripts/$@

target/patterns/gitleaks:
	mkdir -p $@

target/patterns/gitleaks/7.6.1: target/patterns/gitleaks $(wildcard patterns/gitleaks/7.6.1/*)
	rm -f $@
	for pattern_file in $$(ls patterns/gitleaks/7.6.1/*); do \
		cat $$pattern_file >> $@ && \
		echo >> $@; \
	done

target/patterns/gitleaks/8.12.0: target/patterns/gitleaks $(wildcard patterns/gitleaks/8.12.0/*)
	rm -f $@
	for pattern_file in $$(ls patterns/gitleaks/8.12.0/*); do \
		cat $$pattern_file >> $@ && \
		echo >> $@; \
	done
