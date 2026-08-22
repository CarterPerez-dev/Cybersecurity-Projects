# ©AngelaMos | 2026
# chains.rb
# frozen_string_literal: true

module Marshalsea
  module Chains
    class UnknownChainError < StandardError; end

    @registry = []

    class << self
      def registry
        @registry.dup.freeze
      end

      def register(chain)
        @registry << chain unless @registry.include?(chain)
      end

      def all
        registry
      end

      def find(name)
        all.find { |chain| chain.chain_name == name } ||
          raise(UnknownChainError, name.to_s)
      end

      def for_version(gem_name, version)
        all.select { |chain| chain.target_gem == gem_name && chain.affects?(version) }
      end
    end
  end
end

require_relative "chains/base"

Dir[File.join(__dir__, "chains", "*.rb")].each { |chain| require chain }
