# ©AngelaMos | 2026
# Rakefile
# frozen_string_literal: true

require "rake/testtask"
require "bundler/gem_tasks"

Bundler::GemHelper.tag_prefix = "marshalsea-"

Rake::TestTask.new(:test) do |t|
  t.libs = %w[lib test]
  t.test_files = FileList["test/**/*_test.rb"]
  t.warning = true
end

desc "run the standalone control checks that the minitest suite cannot express"
task :control do
  ruby "-Ilib -Itest test/control_check.rb"
end

task default: %i[test control]
