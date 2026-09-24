"""Structured output contract for a detection session.

One schema, one session, one domain. The orchestrator passes this as
`structured_output_schema` on session create; the session is required to call
provide_structured_output with is_final=true before its turn ends, so a
finished session either produced a conforming document or failed visibly.

Every field here exists because something downstream reads it:
`remediation_route` selects the child-session template, `severity` and
`equivalence` decide whether a child session is opened at all, and
`golden_sha`/`mapping_version` let a finding be traced back to the exact
inputs it was judged against.
"""

SEVERITIES = ["critical", "high", "medium", "low"]
EQUIVALENCE = [
    "semantically_different",   # both sides set the field, meanings differ
    "missing_at_provider",      # golden requires it, provider does not have it
    "extra_at_provider",        # provider has it, golden does not
    "equivalent",               # differs textually, same meaning -- NOT drift
]
ROUTES = ["iac_pr", "provider_api", "human_review"]

DETECTION_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "CDNDriftReport",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "domain",
        "golden_sha",
        "mapping_version",
        "verdict",
        "summary",
        "findings",
    ],
    "properties": {
        "domain": {
            "type": "string",
            "description": "The domain this report covers, exactly as given.",
        },
        "golden_sha": {
            "type": "string",
            "description": (
                "The golden_sha supplied in the prompt, echoed back. Identifies "
                "the golden revision these findings were judged against."
            ),
        },
        "mapping_version": {
            "type": "string",
            "description": "The mapping version supplied in the prompt, echoed back.",
        },
        "verdict": {
            "type": "string",
            "enum": ["in_sync", "drift_detected", "inconclusive"],
            "description": (
                "in_sync: no field drifted. drift_detected: at least one finding. "
                "inconclusive: an input was missing or unreadable and the "
                "comparison could not be completed -- say so in notes rather "
                "than reporting a partial comparison as in_sync."
            ),
        },
        "summary": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "fields_compared",
                "findings_total",
                "by_severity",
                "by_provider",
            ],
            "properties": {
                "fields_compared": {
                    "type": "integer",
                    "minimum": 0,
                    "description": (
                        "Mapped fields actually evaluated for this domain. A "
                        "field the mapping does not scope to this domain is "
                        "not compared and is not counted."
                    ),
                },
                "findings_total": {"type": "integer", "minimum": 0},
                "by_severity": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {s: {"type": "integer", "minimum": 0} for s in SEVERITIES},
                },
                "by_provider": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "akamai": {"type": "integer", "minimum": 0},
                        "cloudflare": {"type": "integer", "minimum": 0},
                    },
                },
            },
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "field",
                    "provider",
                    "severity",
                    "equivalence",
                    "golden_value",
                    "observed_value",
                    "locator",
                    "explanation",
                    "impact",
                    "remediation_route",
                    "confidence",
                ],
                "properties": {
                    "field": {
                        "type": "string",
                        "description": (
                            "The mapping field id, e.g. 'tls.min_version'. Use the "
                            "id from the mapping verbatim; do not invent ids."
                        ),
                    },
                    "provider": {"type": "string", "enum": ["akamai", "cloudflare"]},
                    "severity": {
                        "type": "string",
                        "enum": SEVERITIES,
                        "description": (
                            "The mapping's severity for this field. Only depart "
                            "from it if this domain's exposure genuinely changes "
                            "the risk, and justify that in explanation."
                        ),
                    },
                    "equivalence": {"type": "string", "enum": EQUIVALENCE},
                    "golden_value": {
                        "type": "string",
                        "description": "Golden value, rendered compactly as text.",
                    },
                    "observed_value": {
                        "type": "string",
                        "description": (
                            "Value observed at the provider, rendered compactly. "
                            "Use the empty string when the field is absent."
                        ),
                    },
                    "locator": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["provider_path"],
                        "properties": {
                            "provider_path": {
                                "type": "string",
                                "description": (
                                    "Where in the provider document this was read "
                                    "from -- a JSON path, behavior name, or "
                                    "ruleset/rule id. A reviewer must be able to "
                                    "find it without searching."
                                ),
                            },
                            "golden_path": {
                                "type": "string",
                                "description": "Corresponding location in the golden config.",
                            },
                        },
                    },
                    "explanation": {
                        "type": "string",
                        "description": (
                            "What differs and why the two values are not "
                            "equivalent. Name the mechanism, not the diff: a "
                            "reader who cannot see the documents should "
                            "understand what the provider is actually doing."
                        ),
                    },
                    "impact": {
                        "type": "string",
                        "description": (
                            "The consequence if left in place, specific to this "
                            "domain's role (public site, authenticated banking, "
                            "API, static assets). One or two sentences."
                        ),
                    },
                    "remediation_route": {"type": "string", "enum": ROUTES},
                    "remediation_note": {
                        "type": "string",
                        "description": (
                            "What the fix concretely is: the field to change and "
                            "the target value. Omit if the route is human_review "
                            "because the correct end state is genuinely unclear."
                        ),
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": (
                            "Confidence that this is real drift rather than a "
                            "modelling artifact. Below high, explain why in "
                            "explanation."
                        ),
                    },
                },
            },
        },
        "equivalent_but_different": {
            "type": "array",
            "description": (
                "Fields whose representations differ textually but express the "
                "same intent, and which are therefore deliberately NOT findings. "
                "Reporting these is part of the job: it is how a reviewer sees "
                "the comparison was semantic and not string equality."
            ),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["field", "provider", "why_equivalent"],
                "properties": {
                    "field": {"type": "string"},
                    "provider": {"type": "string", "enum": ["akamai", "cloudflare"]},
                    "why_equivalent": {"type": "string"},
                },
            },
        },
        "unmapped_observations": {
            "type": "array",
            "description": (
                "Provider configuration that looks materially risky but has no "
                "mapping entry, so it could not be compared. Gaps in the mapping "
                "are a finding about the mapping, not about the domain."
            ),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["provider", "provider_path", "observation"],
                "properties": {
                    "provider": {"type": "string", "enum": ["akamai", "cloudflare"]},
                    "provider_path": {"type": "string"},
                    "observation": {"type": "string"},
                },
            },
        },
        "notes": {
            "type": "string",
            "description": (
                "Anything a reviewer needs that the fields above cannot carry: "
                "inputs that were missing, assumptions made, why the verdict is "
                "inconclusive."
            ),
        },
    },
}
