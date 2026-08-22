# ©AngelaMos | 2026
# constants.rb
# frozen_string_literal: true

module Marshalsea
  module Marshal
    module Constants
      MAJOR_VERSION = 4
      MINOR_VERSION = 8
      HEADER_LENGTH = 2

      TAG_NIL = "0"
      TAG_TRUE = "T"
      TAG_FALSE = "F"
      TAG_FIXNUM = "i"
      TAG_BIGNUM = "l"
      TAG_FLOAT = "f"
      TAG_STRING = '"'
      TAG_SYMBOL = ":"
      TAG_SYMLINK = ";"
      TAG_OBJECT_LINK = "@"
      TAG_ARRAY = "["
      TAG_HASH = "{"
      TAG_HASH_DEFAULT = "}"
      TAG_REGEXP = "/"
      TAG_OBJECT = "o"
      TAG_USERDEF = "u"
      TAG_USERMARSHAL = "U"
      TAG_USERCLASS = "C"
      TAG_EXTENDED = "e"
      TAG_CLASS = "c"
      TAG_MODULE = "m"
      TAG_MODULE_OLD = "M"
      TAG_STRUCT = "S"
      TAG_DATA = "d"
      TAG_IVAR = "I"

      NUL_BYTE = "\x00"

      FLOAT_NAN = "nan"
      FLOAT_INFINITY = "inf"
      FLOAT_NEGATIVE_INFINITY = "-inf"

      FLOAT_LEADING_SPACE = "[ \t\n\v\f\r]*"
      FLOAT_HEX_PREFIX = /\A#{FLOAT_LEADING_SPACE}[+-]?0[xX](?:\h+(?:\.\h*)?|\.\h+)(?:[pP][+-]?\d+)?/
      FLOAT_DECIMAL_PREFIX = /\A#{FLOAT_LEADING_SPACE}[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?/

      BIGNUM_SIGN_POSITIVE = "+"
      BIGNUM_SIGN_NEGATIVE = "-"
      BIGNUM_SIGNS = [BIGNUM_SIGN_POSITIVE, BIGNUM_SIGN_NEGATIVE].freeze
      BIGNUM_WORD_BYTES = 2

      FIXNUM_INLINE_OFFSET = 5
      FIXNUM_MAX_INLINE = 4
      FIXNUM_MIN_INLINE = -4
      FIXNUM_MAX_WIDTH = 4

      BYTE_SIGN_THRESHOLD = 128
      BYTE_MODULUS = 256
      BITS_PER_BYTE = 8

      DEFAULT_MAX_DEPTH = 256

      ROLE_LENGTH = "byte length"
      ROLE_ARRAY = "array element"
      ROLE_HASH = "hash entry"
      ROLE_IVAR = "instance variable"
      ROLE_STRUCT = "struct member"
      ROLE_BIGNUM = "bignum word"

      ROLE_ANOMALY = "%s name slot holds %s, not a symbol"

      CLASS_NAME_TYPES = %i[symbol symlink].freeze

      RANGE_CLASS_NAME = "Range"
      RANGE_ENDPOINT_IVARS = %i[begin end].freeze

      REGISTERED_WRAPPER_TYPES = %i[data].freeze

      SINK_TAGS = [TAG_USERDEF, TAG_USERMARSHAL, TAG_DATA].freeze

      SINK_METHODS = {
        TAG_USERDEF => "_load",
        TAG_USERMARSHAL => "marshal_load",
        TAG_DATA => "_load_data"
      }.freeze

      GATED_SINK_TAGS = [TAG_USERDEF, TAG_USERMARSHAL, TAG_DATA].freeze
    end
  end
end
