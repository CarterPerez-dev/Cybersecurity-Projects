#!/usr/bin/env bash
# ©AngelaMos | 2026
# package-gate.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BUILD_IMAGE="ruby:4.0-slim"
FLOOR_IMAGE="ruby:3.4-slim"
BELOW_FLOOR_IMAGE="ruby:3.3-slim"
DECLARED_FLOOR=">= 3.4"

WORK="${HERE}/tmp/package"
OBSERVED="${WORK}/observed"
OWNER="$(id -u):$(id -g)"
GIVEN="${1:-}"

INVALID_SIGN_STREAM='"\x04\x08l!\x06\x01\x00".b'

run() {
    docker run --rm --network none --user "${OWNER}" -e HOME=/tmp "$@"
}

record() {
    tee -a "${OBSERVED}" | sed 's/^/  /'
}

echo "packaging gate"
echo

rm -rf "${WORK}"
mkdir -p "${WORK}/build" "${WORK}/ships-target" "${WORK}/drifted"
: >"${OBSERVED}"

echo "=== 1 build ==="
if [[ -n "${GIVEN}" ]]; then
    GEM_DIR="$(cd "$(dirname "${GIVEN}")" && pwd)"
    GEM_FILE="$(basename "${GIVEN}")"
    echo "  auditing a pre-built artifact, no build performed"
    echo "  ${GEM_DIR}/${GEM_FILE}"
    echo "gem_built=true" | record
else
    GEM_DIR="${WORK}/build"
    GEM_FILE="marshalsea-$(run -v "${HERE}:/src:ro" -w /src "${BUILD_IMAGE}" \
        ruby -e 'require "./lib/marshalsea/version"; print Marshalsea::VERSION').gem"

    run -v "${HERE}:/src:ro" -v "${WORK}/build:/out" -w /out "${BUILD_IMAGE}" sh -c '
        set -e
        cd /src && ruby -e "puts Gem::Specification.load(%q{marshalsea.gemspec}).files" >/out/declared.txt
        cd /out && tar -C /src -T declared.txt -cf - | tar -xf -
        cp /src/marshalsea.gemspec /out/
        gem build --strict marshalsea.gemspec
    ' 2>&1 | sed 's/^/  /'

    if [[ -f "${GEM_DIR}/${GEM_FILE}" ]]; then
        echo "gem_built=true" | record
    else
        echo "gem_built=false" | record
    fi
fi
echo

echo "=== 2 manifest audit ==="
run -v "${HERE}:/src:ro" -v "${GEM_DIR}:/gem:ro" "${BUILD_IMAGE}" \
    ruby /src/scripts/audit_gem.rb "/gem/${GEM_FILE}" /src "${DECLARED_FLOOR}" /tmp/extract 2>&1 | record
echo

echo "=== 3 install path ==="
install_and_use() {
    local image="$1"
    local label="$2"

    docker run --rm --network none -v "${GEM_DIR}:/gem:ro" -w / "${image}" sh -c "
        set -e
        gem install --local --no-document /gem/${GEM_FILE} >/dev/null
        ruby -e '
          require \"marshalsea\"
          raise \"loaded from the worktree\" unless Gem.loaded_specs[\"marshalsea\"]
          blob = Marshal.dump(Gem::Requirement.new(\">= 0\"))
          result = Marshalsea::Marshal::Parser.new(blob).parse
          sinks = result.sinks.map { |s| \"#{s.class_name}##{s.sink_method}\" }
          decision = Marshalsea::Marshal::BoundaryDetector.new.inspect_stream(blob)
          ok = result.class_names.include?(\"Gem::Requirement\") &&
               sinks.include?(\"Gem::Requirement#marshal_load\") &&
               decision.blocked? &&
               !defined?(Marshalsea::Marshal::FloatBody).nil?
          puts \"installed_gem_works_on_${label}=#{ok}\"
        '
    " 2>&1 | tail -1
}

install_and_use "${FLOOR_IMAGE}" floor | record
install_and_use "${BUILD_IMAGE}" current | record
echo

echo "=== 4 release identity ==="
release_tag="$(run -v "${HERE}:/app:ro" -w /app "${BUILD_IMAGE}" \
    ruby -e 'require "rake"; load "Rakefile"; print Bundler::GemHelper.instance.send(:version_tag)' 2>/dev/null)"
gem_version="$(run -v "${HERE}:/app:ro" -w /app "${BUILD_IMAGE}" \
    ruby -e 'require "./lib/marshalsea/version"; print Marshalsea::VERSION' 2>/dev/null)"
echo "  rake release would tag: ${release_tag}"
echo "release_tag_is_namespaced=$([[ ${release_tag} == "marshalsea-v${gem_version}" ]] && echo true || echo false)" | record

bare_tag="$(run -v "${HERE}:/app:ro" -w /tmp "${BUILD_IMAGE}" sh -c '
    cp -r /app/lib /app/marshalsea.gemspec /app/README.md /app/LICENSE /tmp/ 2>/dev/null
    printf "require \"rake\"\nrequire \"bundler/gem_tasks\"\n" >/tmp/Rakefile
    ruby -e "require \"rake\"; load \"Rakefile\"; print Bundler::GemHelper.instance.send(:version_tag)"
' 2>/dev/null)"
echo "control_bare_rakefile_tags_the_whole_monorepo=$([[ ${bare_tag} == "v${gem_version}" ]] && echo true || echo false)" | record
echo

echo "=== 5 the floor is measured, not asserted ==="
suite_status=0
for suite in marshal/parser_test scanner_test chains_test marshal/boundary_detector_test \
             marshal/load_guard_test psych/inspector_test corpus_test; do
    if ! docker run --rm --network none -v "${HERE}:/app:ro" -w /app "${FLOOR_IMAGE}" \
        ruby -Ilib -Itest "test/${suite}.rb" >/dev/null 2>&1; then
        echo "  ${suite} is RED on the floor image"
        suite_status=1
    fi
done
if [[ ${suite_status} -eq 0 ]]; then
    echo "suite_green_on_floor=true" | record
else
    echo "suite_green_on_floor=false" | record
fi

differential() {
    local image="$1"
    local label="$2"

    docker run --rm --network none -v "${HERE}:/app:ro" -w /app "${image}" ruby -Ilib -e "
        require \"marshalsea\"
        bytes = ${INVALID_SIGN_STREAM}
        ruby_accepts = begin
          Marshal.load(bytes)
          true
        rescue StandardError
          false
        end
        parser_accepts = begin
          Marshalsea::Marshal::Parser.new(bytes).parse
          true
        rescue Marshalsea::Marshal::StreamError
          false
        end
        puts \"${label}_ruby_accepts_invalid_sign=#{ruby_accepts}\"
        puts \"${label}_parser_accepts_invalid_sign=#{parser_accepts}\"
    " 2>&1 | tail -2
}

differential "${FLOOR_IMAGE}" floor | record
differential "${BELOW_FLOOR_IMAGE}" below_floor | record
echo

echo "=== 6 negative controls ==="
cat >"${WORK}/ships-target/marshalsea.gemspec" <<'SPEC'
require_relative "lib/marshalsea/version"

Gem::Specification.new do |spec|
  spec.name = "marshalsea"
  spec.version = Marshalsea::VERSION
  spec.authors = ["Carter Perez"]
  spec.email = ["carterperez2222@gmail.com"]
  spec.summary = "control fixture that deliberately ships the vulnerable target"
  spec.description = "control fixture for package-gate.sh, never published"
  spec.homepage = "https://github.com/CarterPerez-dev/Cybersecurity-Projects"
  spec.license = "AGPL-3.0-or-later"
  spec.required_ruby_version = ">= 3.4"
  spec.files = Dir["lib/**/*.rb", "target/**/*", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]
end
SPEC

run -v "${HERE}:/src:ro" -v "${WORK}/ships-target:/out" -w /out "${BUILD_IMAGE}" sh -c '
    set -e
    tar -C /src -cf - lib target README.md LICENSE | tar -xf -
    gem build marshalsea.gemspec
' >/dev/null 2>&1

control_target="$(run -v "${HERE}:/src:ro" -v "${WORK}/ships-target:/gem:ro" "${BUILD_IMAGE}" \
    ruby /src/scripts/audit_gem.rb "/gem/${GEM_FILE}" /src "${DECLARED_FLOOR}" /tmp/extract 2>/dev/null |
    grep -c '^target_absent=false$')"
echo "control_auditor_rejects_a_gem_shipping_the_target=$([[ ${control_target} == 1 ]] && echo true || echo false)" | record

run -v "${HERE}:/src:ro" -v "${WORK}/drifted:/out" -w /out "${BUILD_IMAGE}" sh -c '
    set -e
    cd /src && ruby -e "puts Gem::Specification.load(%q{marshalsea.gemspec}).files" >/out/declared.txt
    cd /out && tar -C /src -T declared.txt -cf - | tar -xf -
    cp /src/marshalsea.gemspec /out/
    ruby -e "File.write(%q{lib/marshalsea/version.rb}, File.read(%q{lib/marshalsea/version.rb}) + %q{
})"
    gem build marshalsea.gemspec
' >/dev/null 2>&1

control_drift="$(run -v "${HERE}:/src:ro" -v "${WORK}/drifted:/gem:ro" "${BUILD_IMAGE}" \
    ruby /src/scripts/audit_gem.rb "/gem/${GEM_FILE}" /src "${DECLARED_FLOOR}" /tmp/extract 2>/dev/null |
    grep -c '^lib_matches_worktree=false$')"
echo "control_auditor_rejects_a_drifted_lib_file=$([[ ${control_drift} == 1 ]] && echo true || echo false)" | record

if docker run --rm --network none -v "${GEM_DIR}:/gem:ro" -w / "${BELOW_FLOOR_IMAGE}" \
    gem install --local --no-document "/gem/${GEM_FILE}" >/dev/null 2>&1; then
    echo "control_floor_blocks_install_below_it=false" | record
else
    echo "control_floor_blocks_install_below_it=true" | record
fi
echo

failures=0
expect() {
    if grep -qx "$1=true" "${OBSERVED}"; then
        echo "  PASS   $2"
    else
        echo "  FAIL   $2"
        failures=$((failures + 1))
    fi
}

reject() {
    if grep -qx "$1=false" "${OBSERVED}"; then
        echo "  PASS   $2"
    else
        echo "  FAIL   $2"
        failures=$((failures + 1))
    fi
}

echo "=== verdict ==="
expect gem_built "the gem builds with --strict from its declared manifest alone"
expect every_declared_file_shipped "every file the gemspec declares is in the artifact"
expect nothing_undeclared_shipped "the artifact carries nothing the gemspec did not declare"
expect lib_is_non_empty "the artifact ships a non-empty lib, so the audit is not vacuous"
expect lib_matches_worktree "every shipped lib file is byte-identical to the worktree"
expect floor_is_declared "the artifact declares the floor this gate proves"
expect target_absent "the vulnerable target is absent"
expect tests_absent "the test suite, corpus and fixtures are absent"
expect scripts_absent "the gate scripts are absent"
expect dev_docs_absent "research, plans and agent briefing are absent"
expect build_tooling_absent "justfile, Gemfile, Rakefile and lint config are absent"
expect container_files_absent "Dockerfile and rack config are absent"
expect lab_artifacts_absent "no canary, payload or nested gem artifact shipped"
expect installed_gem_works_on_floor "the installed gem parses, classifies and blocks on the floor"
expect installed_gem_works_on_current "the installed gem parses, classifies and blocks on current"
expect release_tag_is_namespaced "rake release tags marshalsea-vX, not a bare vX the monorepo shares"
expect control_bare_rakefile_tags_the_whole_monorepo "without the tag_prefix line the tag really is bare, so that check is live"
expect suite_green_on_floor "every suite is green on the floor image"
reject floor_ruby_accepts_invalid_sign "on the floor, real Marshal rejects an invalid bignum sign"
reject floor_parser_accepts_invalid_sign "on the floor, the parser rejects it too, so they agree"
expect below_floor_ruby_accepts_invalid_sign "one version below the floor, real Marshal accepts it"
reject below_floor_parser_accepts_invalid_sign "the parser still rejects it, so below the floor they disagree"
expect control_auditor_rejects_a_gem_shipping_the_target "the auditor rejects a gem that ships the target"
expect control_auditor_rejects_a_drifted_lib_file "the auditor rejects a gem whose lib drifted from source"
expect control_floor_blocks_install_below_it "RubyGems refuses to install below the declared floor"

echo
if [[ ${failures} -eq 0 ]]; then
    echo "GATE PASSED"
    exit 0
fi

echo "GATE FAILED (${failures})"
exit 1
