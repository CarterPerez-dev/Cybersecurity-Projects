# ©AngelaMos | 2026
# corpus_test.rb
# frozen_string_literal: true

require_relative "test_helper"
require_relative "support/adversarial_corpus"

module Marshalsea
  class CorpusTest < Minitest::Test
    def detector(allowed = [])
      Marshal::BoundaryDetector.new(allowed_class_names: allowed)
    end

    def test_corpus_covers_both_verdicts
      verdicts = AdversarialCorpus::CASES.map { |c| c[:verdict] }.uniq
      assert_includes verdicts, AdversarialCorpus::VERDICT_ACCEPT
      assert_includes verdicts, AdversarialCorpus::VERDICT_REJECT
    end

    def test_corpus_case_names_are_unique
      names = AdversarialCorpus::CASES.map { |c| c[:name] }
      assert_equal names.length, names.uniq.length
    end

    def test_every_corpus_case_matches_its_verdict
      disagreements = AdversarialCorpus::CASES.filter_map do |kase|
        decision = detector(kase[:allowed]).inspect_stream(kase[:bytes])
        expected = kase[:verdict] == AdversarialCorpus::VERDICT_ACCEPT
        next if decision.proceed? == expected

        verdict = decision.proceed? ? "accept" : "reject"
        "#{kase[:name]}: expected #{kase[:verdict]}, got #{verdict} (#{decision.reason})"
      end

      assert_empty disagreements, "corpus disagreements:\n  #{disagreements.join("\n  ")}"
    end

    def test_parser_never_raises_outside_the_stream_error_hierarchy
      leaks = AdversarialCorpus::CASES.filter_map do |kase|
        detector(kase[:allowed]).inspect_stream(kase[:bytes])
        nil
      rescue Exception => e
        "#{kase[:name]}: #{e.class}"
      end

      assert_empty leaks, "unhandled exceptions escaped the detector:\n  #{leaks.join("\n  ")}"
    end

    def test_allowlisted_cases_would_still_be_rejected_without_their_allowlist
      allowlisted = AdversarialCorpus::CASES.reject { |kase| kase[:allowed].empty? }
      refute_empty allowlisted

      leaks = allowlisted.reject { |kase| detector.inspect_stream(kase[:bytes]).blocked? }
      assert_empty leaks.map { |kase| kase[:name] },
                   "an allowlist must widen what is accepted, never what is rejected"
    end

    def test_every_class_name_slot_carries_byte_identical_gadget
      blind = AdversarialCorpus::CLASS_NAME_SLOTS.reject do |_slot, bytes|
        bytes.include?(AdversarialCorpus::CLASS_NAME_GADGET)
      end

      assert_empty blind.keys,
                   "slot verdicts only compare if the embedded gadget bytes are identical"
    end

    def test_class_name_slots_whose_host_is_not_itself_a_sink_are_all_in_the_corpus
      names = AdversarialCorpus::CASES.map { |kase| kase[:name] }
      missing = AdversarialCorpus::CLASS_NAME_SLOTS_WITH_NON_SINK_HOST.reject do |slot|
        names.include?(:"class_name_slot_#{slot}")
      end

      assert_empty missing, "these slots can flip a detector verdict and must be corpus cases"
    end

    def test_sink_hosted_class_name_slots_are_excluded_from_the_corpus
      hosts = AdversarialCorpus::CLASS_NAME_SLOTS.keys -
              AdversarialCorpus::CLASS_NAME_SLOTS_WITH_NON_SINK_HOST
      names = AdversarialCorpus::CASES.map { |kase| kase[:name] }

      hosts.each do |slot|
        refute_includes names, :"class_name_slot_#{slot}",
                        "#{slot} rejects on its own tag either way, so a corpus case cannot fail"
        assert_predicate detector.inspect_stream(AdversarialCorpus::CLASS_NAME_SLOTS[slot]), :blocked?
      end
    end
  end
end
