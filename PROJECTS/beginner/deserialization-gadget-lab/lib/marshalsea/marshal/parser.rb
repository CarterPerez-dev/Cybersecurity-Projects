# ©AngelaMos | 2026
# parser.rb
# frozen_string_literal: true

module Marshalsea
  module Marshal
    class Parser
      include Constants

      def initialize(source, max_depth: nil, limits: Limits.new)
        raise InputTypeError, "expected String, got #{source.class}" unless source.is_a?(String)

        @limits = limits
        @max_depth = max_depth || limits.max_depth
        enforce_size(source)
        @source = source.dup.force_encoding(Encoding::BINARY)
        @budget = Budget.new(limits)
        @position = 0
        @symbols = []
        @objects = []
        @role_anomalies = []
      end

      def parse
        read_header
        root = read_value(1)
        raise TrailingBytesError, "#{remaining} unread bytes" unless remaining.zero?

        root.each(&:seal)
        Result.new(root, major: @major, minor: @minor,
                         role_anomalies: @role_anomalies.freeze).freeze
      end

      private

      attr_reader :source, :max_depth, :symbols, :objects, :budget, :limits

      def enforce_size(candidate)
        return if candidate.bytesize <= limits.max_bytes

        raise LimitExceededError, "#{Limits::ROLE_BYTES} #{candidate.bytesize} exceeds #{limits.max_bytes}"
      end

      def remaining
        source.bytesize - @position
      end

      def take(count)
        raise MalformedCountError, "negative byte count #{count}" if count.negative?
        raise TruncatedStreamError, "wanted #{count} bytes, had #{remaining}" if count > remaining

        slice = source.byteslice(@position, count)
        @position += count
        slice
      end

      def read_count(role)
        value = read_fixnum
        raise MalformedCountError, "negative #{role} count #{value}" if value.negative?

        value
      end

      def take_byte
        take(1).unpack1("C")
      end

      def take_signed_byte
        byte = take_byte
        byte >= BYTE_SIGN_THRESHOLD ? byte - BYTE_MODULUS : byte
      end

      def read_header
        @major, @minor = take(HEADER_LENGTH).unpack("CC")
        return if @major == MAJOR_VERSION && @minor <= MINOR_VERSION

        raise UnsupportedVersionError, "stream declares #{@major}.#{@minor}"
      end

      def read_fixnum
        marker = take_signed_byte
        return 0 if marker.zero?
        return marker - FIXNUM_INLINE_OFFSET if marker > FIXNUM_MAX_INLINE
        return marker + FIXNUM_INLINE_OFFSET if marker < FIXNUM_MIN_INLINE

        width = marker.abs
        value = little_endian(take(width))
        marker.negative? ? value - (1 << (BITS_PER_BYTE * width)) : value
      end

      def little_endian(bytes)
        bytes.each_byte.with_index.sum { |byte, index| byte << (BITS_PER_BYTE * index) }
      end

      def read_counted_bytes
        size = read_count(ROLE_LENGTH)
        budget.scalar!(size)
        take(size)
      end

      def read_entry_count(role)
        count = read_count(role)
        budget.entries!(count)
        count
      end

      def register(node)
        budget.registered!
        objects << node
        node
      end

      def read_value(depth)
        raise DepthLimitError, "exceeded depth #{max_depth}" if depth > max_depth

        budget.node!
        tag = take(1)

        case tag
        when TAG_NIL then Node.new(type: :nil, tag: tag)
        when TAG_TRUE then Node.new(type: :boolean, tag: tag, value: true)
        when TAG_FALSE then Node.new(type: :boolean, tag: tag, value: false)
        when TAG_FIXNUM then Node.new(type: :fixnum, tag: tag, value: read_fixnum)
        when TAG_SYMBOL then read_symbol(tag)
        when TAG_SYMLINK then read_symlink(tag)
        when TAG_OBJECT_LINK then read_object_link(tag)
        when TAG_BIGNUM then register(read_bignum(tag))
        when TAG_FLOAT then register(read_float(tag))
        when TAG_STRING then register(read_string(tag))
        when TAG_REGEXP then register(read_regexp(tag))
        when TAG_ARRAY then read_array(tag, depth)
        when TAG_HASH, TAG_HASH_DEFAULT then read_hash(tag, depth)
        when TAG_IVAR then read_ivar(tag, depth)
        when TAG_OBJECT then read_object(tag, depth)
        when TAG_STRUCT then read_struct(tag, depth)
        when TAG_USERDEF then register(read_userdef(tag, depth))
        when TAG_USERMARSHAL then read_usermarshal(tag, depth)
        when TAG_DATA then read_wrapped(tag, :data, depth)
        when TAG_USERCLASS then read_wrapped(tag, :user_class, depth)
        when TAG_EXTENDED then read_wrapped(tag, :extended, depth)
        when TAG_CLASS then register(read_named(tag, :class))
        when TAG_MODULE, TAG_MODULE_OLD then register(read_named(tag, :module))
        else raise UnknownTagError, "byte #{tag.unpack1('C')} at offset #{@position - 1}"
        end
      end

      def read_symbol(tag)
        budget.symbol!
        size = read_count(ROLE_LENGTH)
        budget.symbol_name!(size)
        budget.scalar!(size)
        node = Node.new(type: :symbol, tag: tag, value: take(size).to_sym)
        symbols << node.value
        node
      end

      def read_symlink(tag)
        budget.symbol_reference!
        index = read_fixnum
        raise InvalidLinkError, "symlink #{index} of #{symbols.length}" if
          index.negative? || index >= symbols.length

        Node.new(type: :symlink, tag: tag, value: symbols[index])
      end

      def read_object_link(tag)
        budget.link!
        index = read_fixnum
        raise InvalidLinkError, "object link #{index} of #{objects.length}" if
          index.negative? || index >= objects.length

        node = Node.new(type: :object_link, tag: tag, value: index)
        node.link_target = objects[index]
        node
      end

      def read_bignum(tag)
        sign = take(1)
        raise MalformedValueError, "bignum sign #{sign.inspect}" unless BIGNUM_SIGNS.include?(sign)

        size = read_count(ROLE_BIGNUM) * BIGNUM_WORD_BYTES
        budget.scalar!(size)
        magnitude = little_endian(take(size))
        Node.new(type: :bignum, tag: tag,
                 value: sign == BIGNUM_SIGN_NEGATIVE ? -magnitude : magnitude)
      end

      def read_float(tag)
        value, tail = FloatBody.decode(read_counted_bytes)
        Node.new(type: :float, tag: tag, value: value, undecoded_tail: tail)
      end

      def read_string(tag)
        Node.new(type: :string, tag: tag, value: read_counted_bytes)
      end

      def read_regexp(tag)
        node = Node.new(type: :regexp, tag: tag, value: read_counted_bytes)
        node.regexp_options = take_byte
        node
      end

      def read_array(tag, depth)
        node = register(Node.new(type: :array, tag: tag))
        read_entry_count(ROLE_ARRAY).times { node.children << read_value(depth + 1) }
        node
      end

      def read_hash(tag, depth)
        node = register(Node.new(type: :hash, tag: tag))
        read_entry_count(ROLE_HASH).times { node.children << read_pair(depth) }
        node.children << read_value(depth + 1) if tag == TAG_HASH_DEFAULT
        node
      end

      def read_pair(depth)
        pair = Node.new(type: :pair)
        pair.children << read_value(depth + 1)
        pair.children << read_value(depth + 1)
        pair
      end

      def note_role_anomaly(role, node)
        return if CLASS_NAME_TYPES.include?(node.type)

        @role_anomalies << format(ROLE_ANOMALY, role, node.type).freeze
      end

      def read_class_name(node, depth)
        class_node = read_value(depth)
        unless CLASS_NAME_TYPES.include?(class_node.type)
          raise MalformedValueError,
                "class name slot holds #{class_node.type}, not a symbol"
        end

        node.class_name = class_node.value.to_s
        node.auxiliary << class_node
        node
      end

      def read_instance_variables(node, depth)
        count = read_entry_count(ROLE_IVAR)
        budget.instance_variables!(count)
        count.times do
          name = read_value(depth + 1)
          value = read_value(depth + 1)
          note_role_anomaly(ROLE_IVAR, name)
          node.auxiliary << name
          node.auxiliary << value
          node.instance_variables_map[name.value] = value
          node.instance_variable_pairs << [name, value].freeze
        end
        node
      end

      def read_ivar(_tag, depth)
        read_instance_variables(read_value(depth + 1), depth)
      end

      def read_object(tag, depth)
        node = register(Node.new(type: :object, tag: tag))
        read_class_name(node, depth + 1)
        read_instance_variables(node, depth)
      end

      def read_struct(tag, depth)
        node = register(Node.new(type: :struct, tag: tag))
        read_class_name(node, depth + 1)
        count = read_entry_count(ROLE_STRUCT)
        budget.struct_members!(count)
        count.times do
          pair = read_pair(depth)
          note_role_anomaly(ROLE_STRUCT, pair.children.first)
          node.children << pair
        end
        node
      end

      def read_userdef(tag, depth)
        node = Node.new(type: :userdef, tag: tag)
        read_class_name(node, depth + 1)
        node.value = read_counted_bytes
        node
      end

      def read_usermarshal(tag, depth)
        node = register(Node.new(type: :usermarshal, tag: tag))
        read_class_name(node, depth + 1)
        node.children << read_value(depth + 1)
        node
      end

      def read_wrapped(tag, type, depth)
        node = Node.new(type: type, tag: tag)
        register(node) if REGISTERED_WRAPPER_TYPES.include?(type)
        read_class_name(node, depth + 1)
        node.children << read_value(depth + 1)
        node
      end

      def read_named(tag, type)
        size = read_count(ROLE_LENGTH)
        budget.class_name!(size)
        budget.scalar!(size)
        Node.new(type: type, tag: tag, class_name: take(size))
      end
    end
  end
end
