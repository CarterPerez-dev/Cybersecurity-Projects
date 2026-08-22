# ©AngelaMos | 2026
# scanner_test.rb
# frozen_string_literal: true

require_relative "test_helper"
require "tmpdir"

module Marshalsea
  class ScannerTest < Minitest::Test
    SUPPRESSION_NAMESPACE = "Marshalsea::ScannerSuppressionFixture"
    MISSING_SOURCE_PATH = "/nonexistent/marshalsea-scanner-fixture.rb"

    Object.class_eval(<<~SOURCE, MISSING_SOURCE_PATH, 1)
      module Marshalsea
        module ScannerSuppressionFixture
          class VanishedSource
            def hash
              @seed.to_i
            end

            def to_s
              "vanished"
            end
          end
        end
      end
    SOURCE

    def scan(**)
      Scanner.new(**).scan
    end

    def with_exploding(*fixtures)
      fixtures.each { |fixture| fixture.explode = true }
      yield
    ensure
      fixtures.each { |fixture| fixture.explode = false }
    end

    def suppressions_at(report, site)
      report.suppressions.select { |suppression| suppression.site == site }
    end

    def local_scan
      scan(namespace: "Marshalsea::ScannerTest")
    end

    def candidates_for(class_name)
      local_scan.candidates.select { |c| c.class_name == class_name }
    end

    def test_finds_gated_sink_defined_on_a_class
      found = candidates_for("Marshalsea::ScannerTest::GatedFixture")
      assert_equal ["marshal_load"], found.map(&:method_name)
      assert_equal :gated, found.first.gate
    end

    def test_finds_singleton_load_as_gated_sink
      found = candidates_for("Marshalsea::ScannerTest::UserDefFixture")
      assert_includes found.map(&:method_name), "_load"
    end

    def test_finds_ungated_dispatch_method
      found = candidates_for("Marshalsea::ScannerTest::UngatedFixture")
      assert_equal ["hash"], found.map(&:method_name)
      assert_equal :ungated, found.first.gate
    end

    def test_finds_method_missing_as_ungated
      found = candidates_for("Marshalsea::ScannerTest::ProxyFixture")
      assert_includes found.map(&:method_name), "method_missing"
    end

    def test_negative_control_class_with_no_auto_invoked_methods_is_not_reported
      assert_empty candidates_for("Marshalsea::ScannerTest::InertFixture")
    end

    def test_precision_control_inherited_methods_are_not_reported
      assert_empty candidates_for("Marshalsea::ScannerTest::InheritsOnlyFixture")
    end

    def test_candidates_carry_source_location
      candidate = candidates_for("Marshalsea::ScannerTest::GatedFixture").first
      refute_nil candidate.source_location
      assert_includes candidate.source_location, "scanner_test.rb"
    end

    def test_candidates_report_arity
      candidate = candidates_for("Marshalsea::ScannerTest::GatedFixture").first
      assert_equal 1, candidate.arity
    end

    def test_ungated_methods_report_zero_arity
      candidate = candidates_for("Marshalsea::ScannerTest::UngatedFixture").first
      assert_predicate candidate, :zero_arity?
    end

    def test_reachability_via_instance_variable_read
      candidate = candidates_for("Marshalsea::ScannerTest::StatefulFixture").first
      assert_predicate candidate, :touches_state?
      assert_predicate candidate, :reachable?
    end

    def test_reachability_via_implicit_self_call
      candidate = candidates_for("Marshalsea::ScannerTest::AccessorFixture").first
      assert_predicate candidate, :touches_state?, "attr_reader access must count as touching state"
      assert_predicate candidate, :reachable?
    end

    def test_negative_control_stateless_method_is_not_reachable
      candidate = candidates_for("Marshalsea::ScannerTest::StatelessFixture").first
      refute_predicate candidate, :touches_state?
      refute_predicate candidate, :reachable?
    end

    def test_gated_sinks_are_reachable_regardless_of_state
      candidate = candidates_for("Marshalsea::ScannerTest::GatedFixture").first
      assert_predicate candidate, :reachable?
    end

    def test_reachable_is_a_strict_subset_of_candidates
      report = scan(namespace: "Gem")
      refute_empty report.reachable
      assert_operator report.reachable.length, :<, report.candidates.length,
                      "reachability filter kept everything, so it is not filtering"
    end

    def test_rediscovers_accessor_backed_stdlib_sink
      report = scan(namespace: "Gem")
      names = report.reachable.map(&:to_s)
      assert_includes names, "Gem::Requirement#hash"
    end

    def test_rediscovers_a_real_stdlib_sink_without_hardcoding
      report = scan(namespace: "Gem")
      names = report.gated.map { |c| "#{c.class_name}##{c.method_name}" }
      assert_includes names, "Gem::Requirement#marshal_load"
      refute_includes Scanner::GATED_METHODS + Scanner::UNGATED_METHODS, "Gem::Requirement"
    end

    def test_namespace_filter_excludes_everything_else
      report = scan(namespace: "Marshalsea::ScannerTest")
      assert(report.candidates.all? { |c| c.class_name.start_with?("Marshalsea::ScannerTest") })
    end

    def test_report_partitions_every_candidate_by_gate
      report = local_scan
      soft = report.candidates.select(&:soft_gated?)
      buckets = { gated: report.gated, ungated: report.ungated, links: report.links, soft: soft }

      buckets.except(:soft).each do |name, bucket|
        refute_empty bucket, "a partition test proves nothing if #{name} is empty"
      end
      assert_equal report.candidates.length, buckets.values.sum(&:length),
                   "every gate value must land in exactly one bucket, or a candidate is invisible"
      buckets.values.combination(2) { |left, right| assert_empty(left & right) }
    end

    def test_scan_is_deterministic
      first = local_scan.candidates.map(&:to_s).sort
      second = local_scan.candidates.map(&:to_s).sort
      assert_equal first, second
    end

    def test_anonymous_classes_contribute_no_candidate
      anonymous = Class.new { def marshal_load(data); end }
      location = anonymous.instance_method(:marshal_load).source_location.join(":")

      report = scan
      refute_empty report.gated, "the global scan found nothing, so absence proves nothing"
      refute_includes report.candidates.map(&:source_location), location,
                      "a class with no name reached the report"
    end

    def test_scanning_does_not_instantiate_anything
      refute GatedFixture.instantiated
      local_scan
      refute GatedFixture.instantiated, "scanner constructed a candidate class"
    end

    def test_a_clean_scan_reports_no_suppressions
      report = local_scan

      assert_empty report.suppressions
      assert_equal 0, report.suppressed_count
      assert_predicate report, :complete?
      refute_predicate report, :candidates_lost?
    end

    def test_a_lost_candidate_is_counted_and_names_the_class_it_came_from
      control = candidates_for("Marshalsea::ScannerTest::ExplodingHandleFixture")
      assert_equal ["marshal_load"], control.map(&:method_name),
                   "control: this fixture must be discoverable when it is not exploding"

      with_exploding(ExplodingHandleFixture) do
        report = local_scan

        assert_empty(report.candidates.select { |c| c.class_name.end_with?("ExplodingHandleFixture") })
        lost = suppressions_at(report, Scanner::SITE_CANDIDATE)
        assert_equal 1, lost.length
        assert_equal "Marshalsea::ScannerTest::ExplodingHandleFixture#marshal_load", lost.first.subject
        assert_predicate report, :candidates_lost?
        refute_predicate report, :complete?
      end
    end

    def test_a_suppressed_script_error_is_recorded_by_class
      with_exploding(ExplodingHandleFixture) do
        suppression = suppressions_at(local_scan, Scanner::SITE_CANDIDATE).first

        assert_equal "ScriptError", suppression.error_class,
                     "record rescues ScriptError as well as StandardError, so it must report which"
      end
    end

    def test_an_unreadable_method_list_is_counted_as_a_lost_candidate
      with_exploding(ExplodingMethodListFixture) do
        report = local_scan

        assert_empty(report.candidates.select { |c| c.class_name.end_with?("ExplodingMethodListFixture") })
        assert_equal 1, suppressions_at(report, Scanner::SITE_OWN_METHODS).length
        assert_predicate report, :candidates_lost?
      end
    end

    def test_a_module_that_cannot_report_its_name_is_counted
      with_exploding(ExplodingNameFixture) do
        named = suppressions_at(local_scan, Scanner::SITE_MODULE_NAME)

        refute_empty named
        assert_equal Scanner::SUBJECT_UNNAMED, named.first.subject
      end
    end

    def test_unparseable_source_is_counted_without_losing_the_candidate
      report = scan(namespace: SUPPRESSION_NAMESPACE)

      assert_equal ["#{SUPPRESSION_NAMESPACE}::VanishedSource#hash",
                    "#{SUPPRESSION_NAMESPACE}::VanishedSource#to_s"],
                   report.candidates.map(&:to_s),
                   "control: the candidates must survive, only their state analysis failed"
      assert_equal 1, suppressions_at(report, Scanner::SITE_SOURCE_PARSE).length
      refute_predicate report, :candidates_lost?
      refute_predicate report, :complete?
    end

    def test_a_candidate_whose_source_cannot_be_read_stays_reachable
      candidate = scan(namespace: SUPPRESSION_NAMESPACE).candidates.first

      refute_predicate candidate, :state_known?
      refute_predicate candidate, :touches_state?
      assert_predicate candidate, :reachable?,
                       "an unreadable source cannot prove a method inert, and a scanner that " \
                       "drops what it failed to analyse under-reports silently"
    end

    def test_a_c_defined_method_is_reported_as_unanalysable_not_as_inert
      candidate = scan(namespace: "Gem").candidates.find { |c| c.source_location.nil? } ||
                  scan.candidates.find { |c| c.source_location.nil? }

      refute_nil candidate, "control: the stdlib must supply at least one C-defined candidate"
      assert_predicate candidate, :unanalysable?
      refute_predicate candidate, :state_known?
      refute_predicate candidate, :touches_state?,
                       "no Ruby source exists, so the answer is not false, it is unavailable"
    end

    def test_unanalysable_is_distinct_from_an_analysis_that_failed
      vanished = scan(namespace: SUPPRESSION_NAMESPACE).candidates.first
      c_defined = scan.candidates.find { |c| c.source_location.nil? }

      refute_predicate vanished, :unanalysable?,
                       "a source that exists but could not be read is a failure, not an absence"
      assert_predicate c_defined, :unanalysable?
      refute_predicate vanished, :state_known?
      refute_predicate c_defined, :state_known?
    end

    def test_an_unanalysable_candidate_is_never_reachable_on_that_basis
      report = scan
      flooded = report.unanalysable.reject(&:gated?).select(&:reachable?)

      refute_empty report.unanalysable, "control: a stock image must have C-defined candidates"
      assert_empty flooded.first(5).map(&:to_s),
                   "#{flooded.length} C-defined candidates were called reachable purely because " \
                   "they could not be analysed; that is a pass-through, not a filter"
    end

    def test_control_an_unreadable_candidate_is_reachable_on_exactly_that_basis
      unreadable = scan.candidates.select(&:unreadable_source?)
                       .select(&:entry_point?).reject(&:gated?).reject(&:soft_gated?)
                       .select(&:accepts_dispatch?)

      refute_empty unreadable, "control: without one of these the previous test is vacuous"
      assert(unreadable.all?(&:reachable?),
             "the two non-verdicts must behave differently, or splitting them bought nothing")
    end

    def test_the_report_counts_what_it_could_not_analyse
      report = scan

      assert_equal report.candidates.count(&:unanalysable?), report.unanalysable.length
      assert_operator report.unanalysable.length, :>, 0
      refute_predicate report, :fully_analysed?
    end

    def test_a_report_over_analysable_code_only_is_fully_analysed
      report = local_scan

      assert_empty report.unanalysable
      assert_predicate report, :fully_analysed?
    end

    def test_an_analysed_candidate_reports_its_state_as_known
      %w[StatefulFixture StatelessFixture].each do |fixture|
        candidate = candidates_for("Marshalsea::ScannerTest::#{fixture}").first

        assert_predicate candidate, :state_known?,
                         "control: a readable source must produce a verdict, or unknown means nothing"
      end
    end

    def test_one_unreadable_file_is_counted_once_not_once_per_candidate
      report = scan(namespace: SUPPRESSION_NAMESPACE)

      assert_operator report.candidates.length, :>, 1,
                      "control: one candidate cannot expose per-candidate inflation"
      assert_equal 1, report.suppressed_count,
                   "the parse cache must remember a failure, or the count inflates per candidate"
    end

    def test_suppressions_by_site_accounts_for_every_suppression
      with_exploding(ExplodingHandleFixture, ExplodingMethodListFixture, ExplodingNameFixture) do
        report = local_scan
        by_site = report.suppressions_by_site

        assert_equal report.suppressed_count, by_site.values.sum
        assert_equal 3, by_site.keys.length
        assert(by_site.keys.all? { |site| Scanner::SITES.include?(site) })
      end
    end

    def test_a_gated_hook_that_cannot_accept_the_call_is_not_reachable
      wrong = candidates_for("Marshalsea::ScannerTest::WrongArityFixture").first
      right = candidates_for("Marshalsea::ScannerTest::GatedFixture").first

      assert_equal 0, wrong.arity
      refute_predicate wrong, :accepts_dispatch?,
                       "Marshal.load calls marshal_load with one argument, so an arity-0 hook " \
                       "raises ArgumentError and the chain is dead"
      refute_predicate wrong, :reachable?
      assert_predicate right, :accepts_dispatch?, "control: the arity-1 hook must still qualify"
      assert_predicate right, :reachable?
    end

    def test_an_ungated_entry_point_that_takes_an_argument_is_still_reachable
      candidate = candidates_for("Marshalsea::ScannerTest::ComparableFixture").first

      assert_equal "<=>", candidate.method_name
      assert_equal 1, candidate.arity
      refute_predicate candidate, :zero_arity?
      assert_predicate candidate, :reachable?,
                       "Range#marshal_load supplies the argument, so arity 1 is what <=> must " \
                       "have, not a reason to drop it"
    end

    def test_a_link_method_is_recorded_and_never_called_an_entry_point
      candidate = candidates_for("Marshalsea::ScannerTest::LinkFixture").first

      assert_equal "to_s", candidate.method_name
      assert_predicate candidate, :link?
      refute_predicate candidate, :entry_point?
      refute_predicate candidate, :reachable?,
                       "research 02 4.2 verified Marshal.load never invokes to_s directly, so " \
                       "reporting it as reachable is a false positive"
      assert_includes local_scan.links.map(&:to_s), "Marshalsea::ScannerTest::LinkFixture#to_s",
                      "a link is how a chain continues and must not be discarded either"
    end

    def test_a_private_singleton_load_is_discovered
      found = candidates_for("Marshalsea::ScannerTest::PrivateLoadFixture")

      assert_equal ["_load"], found.map(&:method_name),
                   "Marshal.load reaches _load through rb_funcallv, which ignores visibility"
      assert_predicate found.first, :gated?
      assert_predicate found.first, :reachable?
    end

    def test_control_a_public_singleton_load_is_still_discovered
      assert_includes candidates_for("Marshalsea::ScannerTest::UserDefFixture").map(&:method_name),
                      "_load"
    end

    BROKEN_SOURCE_PATH = File.join(Dir.tmpdir, "marshalsea-broken-fixture.rb")

    File.write(BROKEN_SOURCE_PATH, "class Unterminated\n  def hash\n    \"open\n")
    Object.class_eval(<<~SOURCE, BROKEN_SOURCE_PATH, 2)
      module Marshalsea
        module ScannerRecoveredFixture
          class Recovered
            def hash
              @seed.to_i
            end
          end
        end
      end
    SOURCE

    def test_a_recovered_prism_parse_is_a_suppression_not_a_verdict
      report = scan(namespace: "Marshalsea::ScannerRecoveredFixture")
      candidate = report.candidates.first

      assert_equal 1, suppressions_at(report, Scanner::SITE_SOURCE_PARSE).length,
                   "Prism is error tolerant, so a file it could not parse must be counted"
      refute_predicate candidate, :state_known?,
                       "a tree recovered from syntax errors cannot support a true or false verdict"
      assert_predicate candidate, :unreadable_source?
      assert_predicate candidate, :reachable?, "an unreadable source must fail open"
    end

    def test_control_prism_really_does_recover_a_definition_from_that_file
      parsed = Prism.parse_file(BROKEN_SOURCE_PATH)

      assert_predicate parsed, :failure?
      refute_empty parsed.errors
      refute_nil parsed.value,
                 "control: if Prism returned nothing there would be no wrong verdict to prevent"
    end

    class WrongArityFixture
      def marshal_load; end
    end

    class ComparableFixture
      def <=>(other)
        @seed <=> other
      end
    end

    class LinkFixture
      def to_s
        @seed.to_s
      end
    end

    class PrivateLoadFixture
      def self._load(_data)
        allocate
      end
      private_class_method :_load
    end

    class ExplodingNameFixture
      @explode = false

      class << self
        attr_accessor :explode

        def name
          raise NameError, "name unavailable" if @explode

          super
        end
      end
    end

    class ExplodingMethodListFixture
      @explode = false

      class << self
        attr_accessor :explode

        def instance_methods(include_super = true)
          raise NoMethodError, "method list unavailable" if @explode

          super
        end
      end

      def marshal_load(data); end
    end

    class ExplodingHandleFixture
      @explode = false

      class << self
        attr_accessor :explode

        def instance_method(name)
          raise ScriptError, "handle unavailable" if @explode

          super
        end
      end

      def marshal_load(data); end
    end

    class GatedFixture
      @instantiated = false

      class << self
        attr_accessor :instantiated
      end

      def marshal_load(data); end
    end

    class UserDefFixture
      def self._load(_data)
        allocate
      end
    end

    class UngatedFixture
      def hash
        super
      end
    end

    class ProxyFixture
      def method_missing(name, *args)
        super
      end

      def respond_to_missing?(name, include_private = false)
        super
      end
    end

    class StatefulFixture
      def hash
        @seed.to_i
      end
    end

    class AccessorFixture
      attr_reader :seed

      def hash
        seed.to_i
      end
    end

    class StatelessFixture
      def hash
        42
      end
    end

    class InertFixture
      def ordinary_method; end

      def another_one(argument); end
    end

    class InheritsOnlyFixture
    end
  end
end
