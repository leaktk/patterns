PATTERN_FILES := target/patterns/gitleaks/7.6.1
PATTERN_FILES += target/patterns/gitleaks/8.18.2
PATTERN_FILES += target/patterns/gitleaks/8.27.0
PATTERN_FILES += target/patterns/leaktk/1

.PHONY: build
build: $(PATTERN_FILES)

.PHONY: clean
clean:
	rm -rf target

format:
	black tests
	grep -lPR '\t' patterns/ | xargs -r sed -i 's/\t/  /g'
	./scripts/sort-and-group-in-place ./testdata/leaktk-scanner-results.yaml
	./scripts/sort-and-group-in-place ./testdata/gitleaks-7.6.1-results.yaml

.PHONY: test
test: clean build
	@./scripts/$@

target/patterns/gitleaks:
	mkdir -p $@

target/patterns/leaktk:
	mkdir -p $@

target/patterns/gitleaks/7.6.1: target/patterns/gitleaks $(wildcard patterns/gitleaks/7.6.1/*)
	./scripts/compile --provider=gitleaks patterns/gitleaks/7.6.1 > $@

target/patterns/gitleaks/8.18.2: target/patterns/gitleaks $(wildcard patterns/gitleaks/8.18.2/*)
	./scripts/compile --provider=gitleaks patterns/gitleaks/8.18.2 > $@

target/patterns/gitleaks/8.27.0: target/patterns/gitleaks $(wildcard patterns/gitleaks/8.27.0/*)
	./scripts/compile --provider=gitleaks patterns/gitleaks/8.27.0 > $@

target/patterns/leaktk/1: target/patterns/leaktk $(wildcard patterns/leaktk/1/*)
	./scripts/compile --provider=leaktk patterns/leaktk/1 > $@

update-fake-leaks:
	cd testdata/fake-leaks && git checkout main && git pull
	if [[ -n "$$(git status -s)" ]]; then git add testdata/fake-leaks && git commit -m "Update fake-leaks commit"; fi
