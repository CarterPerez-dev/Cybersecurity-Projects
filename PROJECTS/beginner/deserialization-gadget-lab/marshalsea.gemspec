# ©AngelaMos | 2026
# marshalsea.gemspec
# frozen_string_literal: true

require_relative "lib/marshalsea/version"

Gem::Specification.new do |spec|
  spec.name = "marshalsea"
  spec.version = Marshalsea::VERSION
  spec.authors = ["Carter Perez"]
  spec.email = ["carterperez@angelamos.com"]

  spec.summary = "Ruby object-deserialization security lab: inspect, understand, and defend against gadget chains"
  spec.description = "marshalsea parses Ruby Marshal streams without deserializing them, discovers " \
                     "gadget sinks by runtime reflection, and ships the defenses that stop them. Built " \
                     "as a teaching artifact for the deserialization vulnerability class."
  spec.homepage = "https://github.com/CarterPerez-dev/Cybersecurity-Projects"
  spec.license = "AGPL-3.0-or-later"

  spec.required_ruby_version = ">= 3.4"

  spec.metadata = {
    "source_code_uri" => "#{spec.homepage}/tree/main/PROJECTS/beginner/deserialization-gadget-lab",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "documentation_uri" => "#{spec.homepage}/tree/main/PROJECTS/beginner/deserialization-gadget-lab/learn",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir[
    "lib/**/*.rb",
    "README.md",
    "LICENSE"
  ]

  spec.require_paths = ["lib"]
end
