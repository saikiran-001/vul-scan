"""
scoring.py -- turns three module scores into one number and one letter.

The brief asks for a 0-100 score and a grade such as "B+". It also gives the
header rule (+10 present / -10 missing). We combine the modules with weights:

    final = headers * 0.40 + ssl * 0.40 + cms * 0.20

Weights live here (not in the check modules) so you can tune the product in
one place. The grade bands are the familiar US-style letter grades.
"""

# Each module already carries its own weight, but we keep a copy here so the
# formula is readable and testable on its own.
WEIGHTS = {
    "headers": 0.40,   # security headers are the easiest thing to fix, so they matter
    "ssl": 0.40,       # TLS protects everything in transit
    "cms": 0.20,       # only relevant for sites that actually run a CMS
}

# Highest band first: the first band the score satisfies wins.
GRADE_BANDS = [
    (93, "A"),    # excellent
    (90, "A-"),
    (87, "B+"),
    (83, "B"),
    (80, "B-"),
    (77, "C+"),
    (73, "C"),
    (70, "C-"),
    (67, "D+"),
    (63, "D"),
    (60, "D-"),
    (0, "F"),     # below 60
]


def overall_score(modules) -> int:
    """Combine the module scores using their weights."""

    if not modules:                       # a scan with no modules cannot have a score
        return 0

    total = 0.0                           # accumulate the weighted average
    for module in modules:                # each ModuleResult
        weight = WEIGHTS.get(module.id, module.weight)   # prefer the central table
        total += module.score * weight    # e.g. 80 * 0.40 = 32

    return int(round(total))              # the brief wants a whole number


def grade_for(score: int) -> str:
    """Map a 0-100 score to a letter grade."""

    for threshold, letter in GRADE_BANDS:   # bands are sorted from highest to lowest
        if score >= threshold:              # first match is the right band
            return letter
    return "F"                              # unreachable, but explicit


def grade_color(score: int) -> str:
    """A colour name the UI can use for the gauge."""

    if score >= 80:
        return "green"      # healthy
    if score >= 60:
        return "amber"      # needs work
    return "red"            # act now
