"""
©AngelaMos | 2026
challenge.py
"""

from dataclasses import dataclass

from rveng.engine import patch


Category = str
FOUND_VALUE: Category = "found_value"
IDENTIFIED_SYMBOL: Category = "identified_symbol"
PATCHED_BYTES: Category = "patched_bytes"


class AnswerError(ValueError):
    """
    Raised when a submission cannot be interpreted for its category
    """


@dataclass(frozen = True)
class FoundValue:
    """
    The learner must locate a numeric value or a string
    """

    expected: int | str


@dataclass(frozen = True)
class IdentifiedSymbol:
    """
    The learner must name a function, section, or symbol
    """

    name: str


@dataclass(frozen = True)
class PatchedBytes:
    """
    The learner must edit bytes to match a known-good patched target
    """

    offset: int
    known_good: bytes


AnswerSpec = FoundValue | IdentifiedSymbol | PatchedBytes


@dataclass(frozen = True)
class Challenge:
    """
    A curated challenge: a binary, a mission, an answer, and hidden source
    """

    id: str
    module: str
    title: str
    mission: str
    binary: bytes
    source: str
    answer: AnswerSpec

    @property
    def category(self) -> Category:
        match self.answer:
            case FoundValue():
                return FOUND_VALUE
            case IdentifiedSymbol():
                return IDENTIFIED_SYMBOL
            case PatchedBytes():
                return PATCHED_BYTES
            case _:
                raise AnswerError("unknown answer spec")


@dataclass(frozen = True)
class GradeResult:
    """
    The outcome of grading, revealing source only when correct
    """

    correct: bool
    message: str
    revealed_source: str | None


def normalize_int(text: str) -> int:
    """
    Parse a submitted integer in hex, trailing-h, or decimal form
    """
    token = text.strip().lower()
    if not token:
        raise AnswerError("empty value")
    if token.startswith("0x"):
        return int(token, 16)
    if token.endswith("h"):
        return int(token[:-1], 16)
    return int(token, 10)


def _grade_found_value(spec: FoundValue, submitted: str) -> bool:
    if isinstance(spec.expected, int):
        try:
            return normalize_int(submitted) == spec.expected
        except (AnswerError, ValueError):
            return False
    return submitted.strip().lower() == spec.expected.strip().lower()


def _grade_identified_symbol(spec: IdentifiedSymbol, submitted: str) -> bool:
    return submitted.strip().lower() == spec.name.strip().lower()


def _grade_patched_bytes(spec: PatchedBytes, original: bytes, submitted: bytes) -> bool:
    return patch.verify_patch(original, spec.offset, submitted, spec.known_good)


def grade(challenge: Challenge, submission: str | bytes) -> GradeResult:
    """
    Grade a submission against the challenge answer spec
    """
    spec = challenge.answer
    match spec:
        case FoundValue():
            correct = _grade_found_value(spec, _as_text(submission))
        case IdentifiedSymbol():
            correct = _grade_identified_symbol(spec, _as_text(submission))
        case PatchedBytes():
            try:
                submitted = _as_bytes(submission)
            except AnswerError:
                return GradeResult(False, "invalid patch bytes", None)
            correct = _grade_patched_bytes(spec, challenge.binary, submitted)
        case _:
            raise AnswerError("unknown answer spec")
    if correct:
        return GradeResult(True, "correct", challenge.source)
    return GradeResult(False, "not correct yet", None)


def _as_text(submission: str | bytes) -> str:
    if isinstance(submission, bytes):
        return submission.decode("utf-8", "replace")
    return submission


def _as_bytes(submission: str | bytes) -> bytes:
    if isinstance(submission, str):
        try:
            return bytes.fromhex(submission.strip().replace(" ", ""))
        except ValueError as exc:
            raise AnswerError("submission is not valid hex") from exc
    return submission
