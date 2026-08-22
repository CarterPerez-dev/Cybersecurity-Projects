# ©AngelaMos | 2026
# justfile

set shell := ["bash", "-uc"]

image := "ruby:4.0-slim"
vuln_image := "ruby:4.0.2-slim"
run := "docker run --rm --network none -v $PWD:/app -w /app " + image
run_ro := "docker run --rm --network none -v $PWD:/app:ro -w /app " + image
lint_run := "docker run --rm -v $PWD:/app -w /app " + image
owner := `id -u` + ":" + `id -g`
build_run := "docker run --rm --network none --user " + owner + " -e HOME=/tmp"

default:
    @just --list

test:
    {{run_ro}} ruby -Ilib -Itest test/marshal/parser_test.rb
    {{run_ro}} ruby -Ilib -Itest test/scanner_test.rb
    {{run_ro}} ruby -Ilib -Itest test/chains_test.rb
    {{run_ro}} ruby -Ilib -Itest test/marshal/boundary_detector_test.rb
    {{run_ro}} ruby -Ilib -Itest test/marshal/load_guard_test.rb
    {{run_ro}} ruby -Ilib -Itest test/psych/inspector_test.rb
    {{run_ro}} ruby -Ilib -Itest test/corpus_test.rb

corpus:
    {{run_ro}} ruby -Ilib -Itest -e 'require "marshalsea"; require "support/adversarial_corpus"; Marshalsea::AdversarialCorpus::CASES.each { |k| d = Marshalsea::Marshal::BoundaryDetector.new(allowed_class_names: k[:allowed]); dec = d.inspect_stream(k[:bytes]); puts format("  %-38s %-6s %-10s %s", k[:name], dec.proceed? ? "accept" : "reject", k[:allowed].join(","), dec.reason.to_s[0, 52]) }'

scan namespace="":
    {{run_ro}} ruby -Ilib -e 'require "marshalsea"; ns = "{{namespace}}"; r = Marshalsea::Scanner.new(namespace: ns.empty? ? nil : ns).scan; puts "modules=#{r.scanned_modules} candidates=#{r.candidates.length} gated=#{r.gated.length} reachable=#{r.reachable.length} suppressed=#{r.suppressed_count} candidates_lost=#{r.candidates_lost?}"; puts "analysed=#{r.candidates.count(&:state_known?)} unanalysable=#{r.unanalysable.length} unreadable=#{r.candidates.count(&:unreadable_source?)}"; puts; r.reachable.each { |c| puts format("  %-10s %-46s %s", c.gate, c.to_s, c.source_location) }; unless r.complete?; puts; puts "suppressed errors (this scan under-reports):"; r.suppressions_by_site.each { |site, n| puts format("  %-16s %d", site, n) }; end; unless r.fully_analysed?; puts; puts "#{r.unanalysable.length} candidates have no Ruby source and were never analysed; the reachability filter does not cover them"; end'

control:
    {{run_ro}} ruby -Ilib -Itest test/control_check.rb

lint:
    {{lint_run}} sh -c "set -e; gem install --no-document rubocop rubocop-minitest rubocop-performance rubocop-rake >/dev/null; rubocop --force-exclusion"

check: test control

probe:
    {{run_ro}} ruby /app/test/support/matrix_probe.rb

matrix:
    @bash scripts/version-matrix.sh

exploit:
    @bash scripts/exploit-gate.sh

target:
    @bash scripts/target-gate.sh

target-up:
    docker build -q -f target/Dockerfile -t marshalsea-target:local . >/dev/null
    docker run -d --rm --name marshalsea-target --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,size=1m --cap-drop ALL \
        --security-opt no-new-privileges --pids-limit 128 --memory 256m \
        -p "127.0.0.1:${MARSHALSEA_TARGET_PORT:-47823}:4567" marshalsea-target:local
    @echo "target on http://127.0.0.1:${MARSHALSEA_TARGET_PORT:-47823}"
    @echo "this one is published and therefore NOT egress-isolated; just target is"

target-down:
    -docker rm -f marshalsea-target

detector:
    @bash scripts/detector-gate.sh

package *gem:
    @bash scripts/package-gate.sh {{gem}}

gate: check matrix exploit detector target package

build:
    @mkdir -p tmp/build
    {{build_run}} -v $PWD:/src:ro -v $PWD/tmp/build:/out -w /out {{image}} sh -c "set -e; cd /src && ruby -e 'puts Gem::Specification.load(%q{marshalsea.gemspec}).files' >/out/declared.txt; cd /out && tar -C /src -T declared.txt -cf - | tar -xf -; cp /src/marshalsea.gemspec /out/; gem build --strict marshalsea.gemspec"
    @ls -l tmp/build/*.gem

manifest:
    {{run_ro}} ruby -e 'spec = Gem::Specification.load("marshalsea.gemspec"); puts spec.files.sort; puts; puts "#{spec.files.length} files"'

shell:
    docker run --rm -it --network none -v $PWD:/app -w /app {{image}} bash

pull:
    docker pull {{image}}
    docker pull {{vuln_image}}

clean:
    rm -f *.gem
    rm -rf tmp/build tmp/package
