# ©AngelaMos | 2026
# limits.rb
# frozen_string_literal: true

module Marshalsea
  module Marshal
    class Limits
      DEFAULT_MAX_BYTES = 1_048_576
      DEFAULT_MAX_DEPTH = 64
      DEFAULT_MAX_NODES = 10_000
      DEFAULT_MAX_REGISTERED_OBJECTS = 4_096
      DEFAULT_MAX_SYMBOL_DEFINITIONS = 256
      DEFAULT_MAX_COLLECTION_ENTRIES = 1_024
      DEFAULT_MAX_SCALAR_BYTES = 262_144
      DEFAULT_MAX_TOTAL_SCALAR_BYTES = 524_288
      DEFAULT_MAX_OBJECT_LINKS = 2_048
      DEFAULT_MAX_SYMBOL_REFERENCES = 2_048
      DEFAULT_MAX_SYMBOL_NAME_BYTES = 1_024
      DEFAULT_MAX_CLASS_NAME_BYTES = 1_024
      DEFAULT_MAX_INSTANCE_VARIABLES = 256
      DEFAULT_MAX_STRUCT_MEMBERS = 256

      ROLE_BYTES = "stream bytes"
      ROLE_NODES = "nodes"
      ROLE_REGISTERED = "registered objects"
      ROLE_SYMBOLS = "symbol definitions"
      ROLE_ENTRIES = "collection entries"
      ROLE_SCALAR = "scalar bytes"
      ROLE_TOTAL_SCALAR = "total scalar bytes"
      ROLE_LINKS = "object links"
      ROLE_SYMBOL_REFERENCES = "symbol references"
      ROLE_SYMBOL_NAME = "symbol name bytes"
      ROLE_CLASS_NAME = "class name bytes"
      ROLE_INSTANCE_VARIABLES = "instance variables"
      ROLE_STRUCT_MEMBERS = "struct members"

      UNBOUNDED = Float::INFINITY

      attr_reader :max_bytes, :max_depth, :max_nodes, :max_registered_objects,
                  :max_symbol_definitions, :max_collection_entries,
                  :max_scalar_bytes, :max_total_scalar_bytes, :max_object_links,
                  :max_symbol_references, :max_symbol_name_bytes, :max_class_name_bytes,
                  :max_instance_variables, :max_struct_members

      def initialize(
        max_bytes: DEFAULT_MAX_BYTES,
        max_depth: DEFAULT_MAX_DEPTH,
        max_nodes: DEFAULT_MAX_NODES,
        max_registered_objects: DEFAULT_MAX_REGISTERED_OBJECTS,
        max_symbol_definitions: DEFAULT_MAX_SYMBOL_DEFINITIONS,
        max_collection_entries: DEFAULT_MAX_COLLECTION_ENTRIES,
        max_scalar_bytes: DEFAULT_MAX_SCALAR_BYTES,
        max_total_scalar_bytes: DEFAULT_MAX_TOTAL_SCALAR_BYTES,
        max_object_links: DEFAULT_MAX_OBJECT_LINKS,
        max_symbol_references: DEFAULT_MAX_SYMBOL_REFERENCES,
        max_symbol_name_bytes: DEFAULT_MAX_SYMBOL_NAME_BYTES,
        max_class_name_bytes: DEFAULT_MAX_CLASS_NAME_BYTES,
        max_instance_variables: DEFAULT_MAX_INSTANCE_VARIABLES,
        max_struct_members: DEFAULT_MAX_STRUCT_MEMBERS
      )
        @max_bytes = max_bytes
        @max_depth = max_depth
        @max_nodes = max_nodes
        @max_registered_objects = max_registered_objects
        @max_symbol_definitions = max_symbol_definitions
        @max_collection_entries = max_collection_entries
        @max_scalar_bytes = max_scalar_bytes
        @max_total_scalar_bytes = max_total_scalar_bytes
        @max_object_links = max_object_links
        @max_symbol_references = max_symbol_references
        @max_symbol_name_bytes = max_symbol_name_bytes
        @max_class_name_bytes = max_class_name_bytes
        @max_instance_variables = max_instance_variables
        @max_struct_members = max_struct_members
      end

      STACK_SAFE_MAX_DEPTH = Constants::DEFAULT_MAX_DEPTH

      def self.permissive
        new(
          max_bytes: UNBOUNDED,
          max_depth: STACK_SAFE_MAX_DEPTH,
          max_nodes: UNBOUNDED,
          max_registered_objects: UNBOUNDED,
          max_symbol_definitions: UNBOUNDED,
          max_collection_entries: UNBOUNDED,
          max_scalar_bytes: UNBOUNDED,
          max_total_scalar_bytes: UNBOUNDED,
          max_object_links: UNBOUNDED,
          max_symbol_references: UNBOUNDED,
          max_symbol_name_bytes: UNBOUNDED,
          max_class_name_bytes: UNBOUNDED,
          max_instance_variables: UNBOUNDED,
          max_struct_members: UNBOUNDED
        )
      end
    end

    class Budget
      def initialize(limits)
        @limits = limits
        @nodes = 0
        @registered = 0
        @symbols = 0
        @links = 0
        @symbol_references = 0
        @scalar_total = 0
      end

      def node!
        @nodes += 1
        check(@nodes, limits.max_nodes, Limits::ROLE_NODES)
      end

      def registered!
        @registered += 1
        check(@registered, limits.max_registered_objects, Limits::ROLE_REGISTERED)
      end

      def symbol!
        @symbols += 1
        check(@symbols, limits.max_symbol_definitions, Limits::ROLE_SYMBOLS)
      end

      def link!
        @links += 1
        check(@links, limits.max_object_links, Limits::ROLE_LINKS)
      end

      def symbol_reference!
        @symbol_references += 1
        check(@symbol_references, limits.max_symbol_references, Limits::ROLE_SYMBOL_REFERENCES)
      end

      def symbol_name!(size)
        check(size, limits.max_symbol_name_bytes, Limits::ROLE_SYMBOL_NAME)
      end

      def class_name!(size)
        check(size, limits.max_class_name_bytes, Limits::ROLE_CLASS_NAME)
      end

      def instance_variables!(count)
        check(count, limits.max_instance_variables, Limits::ROLE_INSTANCE_VARIABLES)
      end

      def struct_members!(count)
        check(count, limits.max_struct_members, Limits::ROLE_STRUCT_MEMBERS)
      end

      def entries!(count)
        check(count, limits.max_collection_entries, Limits::ROLE_ENTRIES)
      end

      def scalar!(size)
        check(size, limits.max_scalar_bytes, Limits::ROLE_SCALAR)
        @scalar_total += size
        check(@scalar_total, limits.max_total_scalar_bytes, Limits::ROLE_TOTAL_SCALAR)
      end

      private

      attr_reader :limits

      def check(value, ceiling, role)
        return if value <= ceiling

        raise LimitExceededError, "#{role} #{value} exceeds #{ceiling}"
      end
    end
  end
end
