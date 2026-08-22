# ©AngelaMos | 2026
# node.rb
# frozen_string_literal: true

module Marshalsea
  module Marshal
    class Node
      STRING_BACKED_TYPES = %i[string regexp].freeze
      WRAPPER_TYPES = %i[user_class extended].freeze

      attr_reader :type, :tag, :children, :instance_variables_map, :instance_variable_pairs,
                  :auxiliary, :undecoded_tail
      attr_accessor :value, :class_name, :link_target, :regexp_options

      def initialize(type:, tag: nil, value: nil, class_name: nil, undecoded_tail: nil)
        @type = type
        @tag = tag
        @value = value
        @class_name = class_name
        @undecoded_tail = undecoded_tail
        @children = []
        @instance_variables_map = {}
        @instance_variable_pairs = []
        @auxiliary = []
      end

      def fully_decoded?
        undecoded_tail.nil?
      end

      def sink?
        Constants::SINK_TAGS.include?(tag)
      end

      def sink_method
        Constants::SINK_METHODS[tag]
      end

      def gated?
        Constants::GATED_SINK_TAGS.include?(tag)
      end

      def dispatches_key_methods?
        !hash_dispatcher.nil? || !eql_dispatcher.nil?
      end

      def hash_dispatcher(seen = {}.compare_by_identity)
        return nil if seen.key?(self)

        seen[self] = true
        return link_target&.hash_dispatcher(seen) if type == :object_link
        return member_dispatcher(:hash_dispatcher, seen) unless class_name
        return nil if WRAPPER_TYPES.include?(type) && string_backed?

        self
      end

      def eql_dispatcher(seen = {}.compare_by_identity)
        return nil if seen.key?(self)

        seen[self] = true
        return link_target&.eql_dispatcher(seen) if type == :object_link
        return member_dispatcher(:eql_dispatcher, seen) unless class_name

        self
      end

      def member_dispatcher(probe, seen)
        children.each do |child|
          found = child.public_send(probe, seen)
          return found if found
        end
        nil
      end

      def range_endpoints
        instance_variable_pairs.filter_map do |name, value|
          next unless Constants::RANGE_ENDPOINT_IVARS.include?(name.value)

          value if value.effective_class_name
        end
      end

      def effective_class_name
        link_target ? link_target.class_name : class_name
      end

      def string_backed?
        wrapped = children.first
        return false unless wrapped

        STRING_BACKED_TYPES.include?(wrapped.type)
      end

      def each(&block)
        return enum_for(:each) unless block

        yield self
        children.each { |child| child.each(&block) }
        auxiliary.each { |child| child.each(&block) }
      end

      def seal
        value.freeze
        class_name.freeze
        undecoded_tail.freeze
        children.freeze
        auxiliary.freeze
        instance_variables_map.freeze
        instance_variable_pairs.freeze
        freeze
      end
    end

    class Result
      attr_reader :root, :major, :minor, :role_anomalies

      def initialize(root, major:, minor:, role_anomalies: [])
        @root = root
        @major = major
        @minor = minor
        @role_anomalies = role_anomalies
      end

      def canonical_version?
        major == Constants::MAJOR_VERSION && minor == Constants::MINOR_VERSION
      end

      def canonical_roles?
        role_anomalies.empty?
      end

      def nodes
        root.each
      end

      def class_names
        nodes.filter_map(&:class_name).uniq
      end

      def sinks
        nodes.select(&:sink?)
      end

      def gated_sinks
        sinks.select(&:gated?)
      end

      def hash_keys
        nodes.select { |node| node.type == :hash }
             .flat_map(&:children)
             .select { |child| child.type == :pair }
             .filter_map { |pair| pair.children.first }
      end

      def dispatching_hash_keys
        hash_keys.select(&:dispatches_key_methods?)
      end

      def hash_dispatching_keys
        hash_keys.filter_map(&:hash_dispatcher)
      end

      def eql_dispatching_keys
        hash_keys.filter_map(&:eql_dispatcher)
      end

      def range_endpoint_dispatchers
        nodes.select { |node| node.effective_class_name == Constants::RANGE_CLASS_NAME }
             .flat_map(&:range_endpoints)
      end
    end
  end
end
