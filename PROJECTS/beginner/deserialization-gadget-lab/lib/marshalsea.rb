# ©AngelaMos | 2026
# marshalsea.rb
# frozen_string_literal: true

require_relative "marshalsea/version"
require_relative "marshalsea/marshal/constants"
require_relative "marshalsea/marshal/errors"
require_relative "marshalsea/marshal/node"
require_relative "marshalsea/marshal/float_body"
require_relative "marshalsea/marshal/limits"
require_relative "marshalsea/marshal/parser"
require_relative "marshalsea/marshal/boundary_detector"
require_relative "marshalsea/marshal/load_guard"
require_relative "marshalsea/psych/inspector"
require_relative "marshalsea/scanner"
require_relative "marshalsea/chains"

module Marshalsea
end
