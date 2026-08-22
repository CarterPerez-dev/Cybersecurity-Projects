# ©AngelaMos | 2026
# inspector.rb
# frozen_string_literal: true

require "psych"

module Marshalsea
  module Psych
    class DocumentError < StandardError; end

    class MalformedDocumentError < DocumentError; end

    class InputTypeError < DocumentError; end

    class LimitExceededError < DocumentError; end

    module Tags
      PATTERN = %r{\A!ruby/(?<kind>[a-z_-]+)(?::(?<class_name>.+))?\z}

      KIND_OBJECT = "object"
      KIND_HASH = "hash"
      KIND_ARRAY = "array"
      KIND_STRING = "string"
      KIND_STRUCT = "struct"
      KIND_EXCEPTION = "exception"
      KIND_MARSHALABLE = "marshalable"

      REVIVAL_METHODS = {
        KIND_OBJECT => "init_with",
        KIND_HASH => "[]=",
        KIND_ARRAY => "init_with",
        KIND_STRING => "init_with",
        KIND_STRUCT => "init_with",
        KIND_EXCEPTION => "init_with",
        KIND_MARSHALABLE => "marshal_load"
      }.freeze

      GATED_KINDS = [KIND_MARSHALABLE].freeze

      module_function

      def parse(tag)
        match = PATTERN.match(tag.to_s)
        return nil unless match

        [match[:kind], match[:class_name]]
      end
    end

    class Limits
      DEFAULT_MAX_BYTES = 1_048_576
      DEFAULT_MAX_DEPTH = 64
      DEFAULT_MAX_NODES = 10_000
      DEFAULT_MAX_ALIASES = 64
      DEFAULT_MAX_DOCUMENTS = 8

      ROLE_BYTES = "document bytes"
      ROLE_DEPTH = "nesting depth"
      ROLE_NODES = "nodes"
      ROLE_ALIASES = "aliases"
      ROLE_DOCUMENTS = "documents"

      attr_reader :max_bytes, :max_depth, :max_nodes, :max_aliases, :max_documents

      def initialize(max_bytes: DEFAULT_MAX_BYTES, max_depth: DEFAULT_MAX_DEPTH,
                     max_nodes: DEFAULT_MAX_NODES, max_aliases: DEFAULT_MAX_ALIASES,
                     max_documents: DEFAULT_MAX_DOCUMENTS)
        @max_bytes = max_bytes
        @max_depth = max_depth
        @max_nodes = max_nodes
        @max_aliases = max_aliases
        @max_documents = max_documents
      end
    end

    class Reference
      attr_reader :class_name, :kind, :key_position

      def initialize(class_name:, kind:, key_position:)
        @class_name = class_name
        @kind = kind
        @key_position = key_position
      end

      def key_position?
        @key_position
      end

      def gated?
        Tags::GATED_KINDS.include?(kind)
      end

      def revival_method
        Tags::REVIVAL_METHODS.fetch(kind, nil)
      end

      def to_s
        "#{class_name} (!ruby/#{kind})"
      end
    end

    class Document
      attr_reader :references, :alias_count, :node_count, :document_count

      def initialize(references:, alias_count:, node_count:, document_count:)
        @references = references
        @alias_count = alias_count
        @node_count = node_count
        @document_count = document_count
      end

      def class_names
        references.filter_map(&:class_name).uniq
      end

      def revivable
        references.reject { |reference| reference.class_name.nil? }
      end

      def key_position_references
        references.select(&:key_position?)
      end

      def gated_references
        references.select(&:gated?)
      end
    end

    class Inspector
      Decision = Marshalsea::Marshal::BoundaryDetector::Decision

      REASON_INPUT_TYPE = "input is not a String"
      REASON_MALFORMED = "document is not parseable YAML: %s"
      REASON_UNAPPROVED = "document revives unapproved class %s through %s"
      REASON_KEY_DISPATCH = "document puts %s in a mapping key, so its #hash and #== run " \
                            "while the mapping is rebuilt"

      LIMITATION_NOTICE = <<~NOTICE
        SECURITY LIMITATION

        Marshalsea::Psych::Inspector reads a YAML document through Psych.parse_stream, which
        builds an AST and revives nothing. It never calls YAML.load or YAML.unsafe_load.

        Unlike Marshal, Psych's own allowlist is a real veto: Psych checks the tag before it
        revives the object, where Marshal runs its proc after the callback has already fired.
        Same intent, opposite outcome, decided entirely by where the check sits. That means
        YAML.safe_load with permitted_classes is a boundary and this inspector is only
        detection and reporting on top of it.

        Prefer YAML.safe_load. Use this to see what a document would revive, to log it, or
        to reject a document before it reaches a loader you do not control.

        Alias expansion is not performed here, so an alias bomb costs nothing to inspect.
        It still costs whatever the eventual loader spends expanding it, which is why the
        alias count is bounded and reported rather than ignored.
      NOTICE

      def initialize(permitted_class_names: [], limits: Limits.new)
        @permitted_class_names = permitted_class_names.map(&:to_s).freeze
        @limits = limits
      end

      def inspect_document(input)
        return reject(REASON_INPUT_TYPE) unless input.is_a?(String)

        snapshot = input.dup.freeze
        enforce_size(snapshot)
        evaluate(read(snapshot), snapshot)
      rescue DocumentError => e
        reject(format(REASON_MALFORMED, e.class.name.split("::").last))
      end

      def read(source)
        Walk.new(limits).call(::Psych.parse_stream(source))
      rescue ::Psych::SyntaxError => e
        raise MalformedDocumentError, e.message
      end

      private

      attr_reader :permitted_class_names, :limits

      def enforce_size(source)
        return if source.bytesize <= limits.max_bytes

        raise LimitExceededError, "#{Limits::ROLE_BYTES} #{source.bytesize} exceeds #{limits.max_bytes}"
      end

      def evaluate(document, snapshot)
        violation = violation_for(document)
        return reject(violation) if violation

        Decision.new(state: Decision::STATE_PROCEED, snapshot: snapshot, result: document)
      end

      def violation_for(document)
        keyed = document.key_position_references.first
        return format(REASON_KEY_DISPATCH, keyed.class_name.inspect) if keyed

        unapproved = document.revivable.reject do |reference|
          permitted_class_names.include?(reference.class_name)
        end
        return nil if unapproved.empty?

        format(REASON_UNAPPROVED, unapproved.first.class_name.inspect,
               unapproved.first.revival_method)
      end

      def reject(reason)
        Decision.new(state: Decision::STATE_BLOCKED, reason: reason)
      end
    end

    class Walk
      MAPPING_KEY_STRIDE = 2

      def initialize(limits)
        @limits = limits
        @references = []
        @aliases = 0
        @nodes = 0
        @documents = 0
      end

      def call(stream)
        @documents = stream.children.length
        check(@documents, limits.max_documents, Limits::ROLE_DOCUMENTS)
        stream.children.each { |child| visit(child, 1, false) }
        Document.new(references: @references.freeze, alias_count: @aliases,
                     node_count: @nodes, document_count: @documents)
      end

      private

      attr_reader :limits

      def check(value, ceiling, role)
        return if value <= ceiling

        raise LimitExceededError, "#{role} #{value} exceeds #{ceiling}"
      end

      def visit(node, depth, key_position)
        check(depth, limits.max_depth, Limits::ROLE_DEPTH)
        @nodes += 1
        check(@nodes, limits.max_nodes, Limits::ROLE_NODES)

        if node.is_a?(::Psych::Nodes::Alias)
          @aliases += 1
          check(@aliases, limits.max_aliases, Limits::ROLE_ALIASES)
        end

        record(node, key_position)
        descend(node, depth)
      end

      def record(node, key_position)
        return unless node.respond_to?(:tag)

        kind, class_name = Tags.parse(node.tag)
        return unless kind

        @references << Reference.new(class_name: class_name, kind: kind, key_position: key_position)
      end

      def descend(node, depth)
        children = node.children
        return unless children

        mapping = node.is_a?(::Psych::Nodes::Mapping)
        children.each_with_index do |child, index|
          visit(child, depth + 1, mapping && (index % MAPPING_KEY_STRIDE).zero?)
        end
      end
    end
  end
end
