# ©AngelaMos | 2026
# matrix_probe.rb
# frozen_string_literal: true

require "json"

GADGET_CLASSES = %w[
  Gem::Requirement
  Gem::Version
  Gem::SpecFetcher
  Gem::Source
  Gem::Source::Git
  Gem::RequestSet::Lockfile
  Gem::URI
  Gem::URI::HTTP
  Gem::Package::TarReader
  Net::BufferedIO
  Net::WriteAdapter
  UncaughtThrowError
].freeze

ERB_GUARD_ANCHOR = :def_method
ERB_DELEGATING_METHODS = %i[def_module def_class].freeze

GUARD_TOKEN = "@_init"
DELEGATION_TOKEN = "def_method"
PATCH_TOKEN = "git_command"
VULNERABLE_TOKEN = "popen(@git"
BINARIES = %w[make rake git].freeze

def gem_version(name)
  spec = Gem.loaded_specs[name]
  return spec.version.to_s if spec

  Gem::Specification.find_all_by_name(name).map(&:version).max&.to_s || "absent"
rescue StandardError
  "unknown"
end

def constant_present?(name)
  Object.const_get(name)
  true
rescue StandardError, ScriptError
  false
end

def binary_present?(name)
  ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).any? do |dir|
    File.executable?(File.join(dir, name))
  end
end

def git_gadget_state
  require "rubygems/source/git"
  path = Gem::Source::Git.instance_method(:cache).source_location&.first
  return "unknown" unless path && File.readable?(path)

  body = File.read(path)
  return "patched" if body.include?(PATCH_TOKEN)
  return "vulnerable" if body.include?(VULNERABLE_TOKEN)

  "unknown"
rescue StandardError, ScriptError
  "unknown"
end

def safe_marshal_state
  require "rubygems/safe_marshal"
  path = Gem::SafeMarshal.method(:safe_load).source_location&.first
  return "unknown" unless path && File.readable?(path)

  File.read(path).include?("Date") ? "permits_date" : "no_date"
rescue StandardError, ScriptError
  "absent"
end

def erb_state
  require "erb"
  {
    "guarded" => erb_method_body(ERB_GUARD_ANCHOR)&.include?(GUARD_TOKEN),
    "delegating" => ERB_DELEGATING_METHODS.select do |name|
      erb_method_body(name)&.include?(DELEGATION_TOKEN)
    end.map(&:to_s)
  }
rescue StandardError, ScriptError
  { "guarded" => nil, "delegating" => [] }
end

def erb_method_body(name)
  path, line = ERB.instance_method(name).source_location
  return nil unless path && File.readable?(path)

  File.readlines(path)[line - 1, 10].to_a.join
rescue StandardError, ScriptError
  nil
end

def marshal_format
  blob = Marshal.dump(nil)
  "#{blob.getbyte(0)}.#{blob.getbyte(1)}"
end

report = {
  "image" => ENV.fetch("MATRIX_IMAGE", "unknown"),
  "ruby" => RUBY_VERSION,
  "rubygems" => Gem::VERSION,
  "psych" => gem_version("psych"),
  "erb" => gem_version("erb"),
  "json" => gem_version("json"),
  "marshal_format" => marshal_format,
  "binaries" => BINARIES.to_h { |name| [name, binary_present?(name)] },
  "classes_baseline" => GADGET_CLASSES.to_h { |name| [name, constant_present?(name)] },
  "git_gadget" => git_gadget_state,
  "safe_marshal" => safe_marshal_state,
  "erb_guard" => erb_state
}

puts JSON.generate(report)
