PATTERN_FILES := target/patterns/gitleaks/7.6.1
PATTERN_FILES += target/patterns/gitleaks/8.18.2

.PHONY: all
all: $(PATTERN_FILES)

.PHONY: clean
clean:
	rm -rf target

format:
	black tests
	grep -lPR '\t' patterns/ | xargs -r sed -i 's/\t/  /g'
	./scripts/sort-and-group-in-place ./testdata/leaktk-scanner-results.yaml
	./scripts/sort-and-group-in-place ./testdata/gitleaks-7.6.1-results.yaml

.PHONY: test
test: clean $(PATTERN_FILES)
	@./scripts/$@

target/patterns/gitleaks:
	mkdir -p $@

target/patterns/gitleaks/7.6.1: target/patterns/gitleaks $(wildcard patterns/gitleaks/7.6.1/*)
	rm -f $@
	for pattern_file in $$(ls patterns/gitleaks/7.6.1/*); do \
		cat $$pattern_file | grep -vE '^\s*(#|$$)' | sed 's/^ *//g' >> $@; \
	done

target/patterns/gitleaks/8.18.2: target/patterns/gitleaks $(wildcard patterns/gitleaks/8.18.2/*)
	rm -f $@
	for pattern_file in $$(ls patterns/gitleaks/8.18.2/*); do \
		cat $$pattern_file | grep -vE '^\s*(#|$$)' | sed 's/^ *//g' >> $@; \
	done
