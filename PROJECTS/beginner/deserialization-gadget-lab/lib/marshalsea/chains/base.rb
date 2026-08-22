# ©AngelaMos | 2026
# base.rb
# frozen_string_literal: true

module Marshalsea
  module Chains
    class ChainError < StandardError; end

    class NotImplementedByChainError < ChainError; end

    class ObjectLinkRefusedError < ChainError; end

    class Base
      SUBCLASS_MUST_DEFINE = "chain must define"

      KIND_PRIMITIVE = :primitive
      KIND_CHAIN = :chain

      HEADER_BYTES = 2
      HASH_WITH_ONE_ENTRY = "{\x06"
      NIL_VALUE = "0"

      OBJECT_LINK_REFUSED = "the payload graph contains an object link, whose index would shift " \
                            "when spliced behind a hash node; build it without repeated objects"

      class << self
        def inherited(subclass)
          super
          Chains.register(subclass)
        end

        def metadata
          raise NotImplementedByChainError, "#{SUBCLASS_MUST_DEFINE} metadata"
        end

        def chain_name
          metadata.fetch(:name)
        end

        def vector
          metadata.fetch(:vector)
        end

        def cve
          metadata.fetch(:cve)
        end

        def target_gem
          metadata.fetch(:gem)
        end

        def kind
          metadata.fetch(:kind)
        end

        def chain?
          kind == KIND_CHAIN
        end

        def primitive?
          kind == KIND_PRIMITIVE
        end

        def required_gems
          metadata.fetch(:requires, [])
        end

        def affected_requirements
          metadata.fetch(:affected).map { |constraint| Gem::Requirement.new(constraint) }
        end

        def affects?(version)
          candidate = Gem::Version.new(version.to_s)
          affected_requirements.any? { |requirement| requirement.satisfied_by?(candidate) }
        end
      end

      def generate
        raise NotImplementedByChainError, "#{SUBCLASS_MUST_DEFINE} generate"
      end

      def serialize
        ::Marshal.dump(generate)
      end

      private

      def in_hash_key_position(object)
        body = ::Marshal.dump(object).byteslice(HEADER_BYTES..)
        header = ::Marshal.dump(nil).byteslice(0, HEADER_BYTES)
        refuse_object_links("#{header}#{HASH_WITH_ONE_ENTRY}#{body}#{NIL_VALUE}".b)
      end

      def refuse_object_links(stream)
        graph = Marshalsea::Marshal::Parser.new(stream).parse
        return stream if graph.nodes.none? { |node| node.type == :object_link }

        raise ObjectLinkRefusedError, OBJECT_LINK_REFUSED
      end
    end
  end
end
