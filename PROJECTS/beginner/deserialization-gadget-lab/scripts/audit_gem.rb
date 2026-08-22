# ©AngelaMos | 2026
# audit_gem.rb
# frozen_string_literal: true

require "rubygems/package"
require "digest"
require "fileutils"

GEM_PATH = ARGV.fetch(0)
TREE = ARGV.fetch(1)
EXPECTED_FLOOR = ARGV.fetch(2)
EXTRACT_ROOT = ARGV.fetch(3)

DOC_FILES = %w[README.md LICENSE].freeze
LIB_PREFIX = "lib/"

FORBIDDEN = {
  "target_absent" => %r{\Atarget/},
  "tests_absent" => %r{\Atest/},
  "scripts_absent" => %r{\Ascripts/},
  "dev_docs_absent" => %r{\Adocs/|\AAGENTS\.md\z},
  "build_tooling_absent" => /\A(justfile|Gemfile|Gemfile\.lock|Rakefile|\.rubocop\.yml|\.gitignore)\z/,
  "container_files_absent" => /Dockerfile|compose|config\.ru/i,
  "lab_artifacts_absent" => %r{\.gem\z|\.marshal\z|\.bin\z|\Apayloads/|\Aloot/|canary}i
}.freeze

def tree_lib_files
  Dir.chdir(TREE) { Dir.glob("#{LIB_PREFIX}**/*.rb").sort }
end

def emit(key, value)
  puts "#{key}=#{value}"
end

def info(label, value)
  puts "INFO #{label}: #{value}"
end

package = Gem::Package.new(GEM_PATH)
spec = package.spec
contents = package.contents.sort
expected = (DOC_FILES + tree_lib_files).sort
shipped_lib = contents.select { |path| path.start_with?(LIB_PREFIX) }

FileUtils.rm_rf(EXTRACT_ROOT)
FileUtils.mkdir_p(EXTRACT_ROOT)
package.extract_files(EXTRACT_ROOT)

missing = expected - contents
unexpected = contents - expected

drifted = shipped_lib.reject do |path|
  source = File.join(TREE, path)
  next false unless File.file?(source)

  Digest::SHA256.file(File.join(EXTRACT_ROOT, path)).hexdigest ==
    Digest::SHA256.file(source).hexdigest
end

orphaned = shipped_lib.reject { |path| File.file?(File.join(TREE, path)) }

info "gem", File.basename(GEM_PATH)
info "declares", "#{spec.name} #{spec.version} ruby #{spec.required_ruby_version}"
info "shipped", "#{contents.length} files, #{shipped_lib.length} under lib/"
info "worktree", "#{tree_lib_files.length} files under lib/"
info "missing", missing.empty? ? "none" : missing.join(", ")
info "unexpected", unexpected.empty? ? "none" : unexpected.join(", ")
info "drifted", drifted.empty? ? "none" : drifted.join(", ")
info "orphaned", orphaned.empty? ? "none" : orphaned.join(", ")

emit "every_declared_file_shipped", missing.empty?
emit "nothing_undeclared_shipped", unexpected.empty?
emit "lib_is_non_empty", shipped_lib.length.positive?
emit "lib_matches_worktree", drifted.empty? && orphaned.empty?
emit "floor_is_declared", spec.required_ruby_version.to_s == EXPECTED_FLOOR

FORBIDDEN.each do |key, pattern|
  emit(key, contents.none? { |path| pattern.match?(path) })
end
