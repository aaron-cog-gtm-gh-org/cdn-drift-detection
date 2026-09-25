"""Structured output contract for a cross-provider detection session.

One schema, one session, one domain. The orchestrator passes this as
`structured_output_schema` on session create; the session is required to call
provide_structured_output with is_final=true before its turn ends, so a
finished session either produced a conforming document or failed visibly.

There is no golden state in this model. Akamai and Cloudflare are compared
against each other, neither is authoritative, and a disagreement is resolved
by a human who tells the session which side is correct. That decision, and
the pull request that carries it into the losing provider's Terraform, are
part of the report: `decisions` records what the human chose, `remediation`
records what was changed as a result.
"""

SEVERITIES = ["critical", "high", "medium", "low"]
PROVIDERS = ["akamai", "cloudflare"]
DISAGREEMENTS = [
    "value_mismatch",        # both sides set the field, meanings differ
    "missing_at_akamai",     # expressible at Akamai, but not configured there
    "missing_at_cloudflare",  # expressible at Cloudflare, but not configured there
]
NOT_COMPARABLE_REASONS = [
    "unsupported_at_akamai",
    "unsupported_at_cloudflare",
    "provider_specific",
]
AUTHORITIES = ["akamai", "cloudflare", "unclear"]

DETECTION_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "CrossProviderDriftReport",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "domain",
        "mapping_version",
        "verdict",
        "summary",
        "findings",
        "fields_reviewed",
    ],
    "properties": {
        "domain": {
            "type": "string",
            "description": "The domain this report covers, exactly as given.",
        },
        "mapping_version": {
            "type": "string",
            "description": "The mapping version supplied in the prompt, echoed back.",
        },
        "iac_sha": {
            "type": "string",
            "description": (
                "The iac_sha supplied in the prompt, echoed back. Identifies the "
                "Terraform revision the remediation branched from."
            ),
        },
        "verdict": {
            "type": "string",
            "enum": ["in_sync", "drift_detected", "inconclusive"],
            "description": (
                "in_sync: the two providers agree on every comparable field. "
                "drift_detected: at least one disagreement. inconclusive: an "
                "input was missing or unreadable and the comparison could not "
                "be completed -- say so in notes rather than reporting a "
                "partial comparison as in_sync."
            ),
        },
        "summary": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "fields_compared",
                "findings_total",
                "by_severity",
            ],
            "properties": {
                "fields_compared": {
                    "type": "integer",
                    "minimum": 0,
                    "description": (
                        "Mapped fields both providers can express, and which "
                        "were therefore actually compared against each other. "
                        "Fields only one provider can express are counted in "
                        "not_comparable instead."
                    ),
                },
                "findings_total": {"type": "integer", "minimum": 0},
                "by_severity": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        s: {"type": "integer", "minimum": 0} for s in SEVERITIES
                    },
                },
            },
        },
        "findings": {
            "type": "array",
            "description": (
                "Fields where the two providers are doing materially different "
                "things. Each one is a question for the human: which side is "
                "correct."
            ),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "field",
                    "severity",
                    "disagreement",
                    "akamai_value",
                    "cloudflare_value",
                    "locator",
                    "explanation",
                    "impact",
                    "recommended_authority",
                    "recommendation_rationale",
                    "confidence",
                ],
                "properties": {
                    "field": {
                        "type": "string",
                        "description": (
                            "The mapping field id, e.g. 'tls.min_version'. Use "
                            "the id from the mapping verbatim; do not invent ids."
                        ),
                    },
                    "severity": {
                        "type": "string",
                        "enum": SEVERITIES,
                        "description": (
                            "The mapping's severity for this field. Only depart "
                            "from it if this domain's exposure genuinely changes "
                            "the risk, and justify that in explanation."
                        ),
                    },
                    "disagreement": {"type": "string", "enum": DISAGREEMENTS},
                    "akamai_value": {
                        "type": "string",
                        "description": (
                            "What Akamai is actually doing, rendered compactly "
                            "as text. Empty string if absent there."
                        ),
                    },
                    "cloudflare_value": {
                        "type": "string",
                        "description": (
                            "What Cloudflare is actually doing, rendered "
                            "compactly as text. Empty string if absent there."
                        ),
                    },
                    "locator": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["akamai_path", "cloudflare_path"],
                        "properties": {
                            "akamai_path": {
                                "type": "string",
                                "description": (
                                    "Where in the Akamai documents this was read "
                                    "from -- a JSON path, behavior name, or "
                                    "policy id. A reviewer must be able to find "
                                    "it without searching."
                                ),
                            },
                            "cloudflare_path": {
                                "type": "string",
                                "description": (
                                    "The corresponding location in the "
                                    "Cloudflare documents."
                                ),
                            },
                        },
                    },
                    "explanation": {
                        "type": "string",
                        "description": (
                            "What differs and why the two values are not "
                            "equivalent. Name the mechanism, not the diff: a "
                            "reader who cannot see the documents should "
                            "understand what each provider is actually doing."
                        ),
                    },
                    "impact": {
                        "type": "string",
                        "description": (
                            "The consequence of the two providers behaving "
                            "differently here, specific to this domain's role "
                            "and to which traffic each provider serves. One or "
                            "two sentences."
                        ),
                    },
                    "recommended_authority": {
                        "type": "string",
                        "enum": AUTHORITIES,
                        "description": (
                            "Which side you believe is correct, offered to the "
                            "human as a recommendation. Use 'unclear' when the "
                            "inputs genuinely do not settle it -- a recommen"
                            "dation you do not believe is worse than none."
                        ),
                    },
                    "recommendation_rationale": {
                        "type": "string",
                        "description": (
                            "Why that side, in terms of risk and intent rather "
                            "than recency. If 'unclear', what evidence would "
                            "settle it."
                        ),
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": (
                            "Confidence that this is a real disagreement rather "
                            "than a modelling artifact. Below high, explain why "
                            "in explanation."
                        ),
                    },
                },
            },
        },
        "decisions": {
            "type": "array",
            "description": (
                "The human's answer, one entry per finding you asked about. "
                "Required whenever findings is non-empty and an answer was "
                "received."
            ),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["field", "authority", "source"],
                "properties": {
                    "field": {"type": "string"},
                    "authority": {
                        "type": "string",
                        "enum": ["akamai", "cloudflare", "neither", "deferred"],
                        "description": (
                            "Which side the human said is correct. 'neither' "
                            "when they gave a third value to converge on "
                            "(record it in note); 'deferred' when they "
                            "explicitly chose not to decide."
                        ),
                    },
                    "source": {
                        "type": "string",
                        "enum": ["user"],
                        "description": (
                            "Always 'user'. A decision you made yourself is not "
                            "a decision -- it is a recommendation, and belongs "
                            "in the finding."
                        ),
                    },
                    "note": {
                        "type": "string",
                        "description": (
                            "The human's reasoning or instruction, quoted or "
                            "closely paraphrased, including any third value "
                            "they specified."
                        ),
                    },
                },
            },
        },
        "remediation": {
            "type": "object",
            "additionalProperties": False,
            "description": (
                "What you changed once the human decided, and where to review "
                "it. Omit entirely if there was nothing to remediate."
            ),
            "required": ["changes"],
            "properties": {
                "pull_request_url": {
                    "type": "string",
                    "description": "URL of the pull request you opened, if any.",
                },
                "branch": {"type": "string"},
                "changes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "field",
                            "provider_changed",
                            "file",
                            "from_value",
                            "to_value",
                        ],
                        "properties": {
                            "field": {"type": "string"},
                            "provider_changed": {
                                "type": "string",
                                "enum": PROVIDERS,
                                "description": (
                                    "The provider whose Terraform you edited -- "
                                    "the one the human said was wrong."
                                ),
                            },
                            "file": {
                                "type": "string",
                                "description": (
                                    "Repo-relative path of the file you edited."
                                ),
                            },
                            "from_value": {"type": "string"},
                            "to_value": {
                                "type": "string",
                                "description": (
                                    "The new value, expressed in the edited "
                                    "provider's own vocabulary and units -- not "
                                    "a copy of the other provider's literal."
                                ),
                            },
                        },
                    },
                },
                "unresolved": {
                    "type": "array",
                    "description": (
                        "Decided fields you could not express as code, with the "
                        "reason. Leaving one here is legitimate; silently "
                        "dropping it is not."
                    ),
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["field", "reason"],
                        "properties": {
                            "field": {"type": "string"},
                            "reason": {"type": "string"},
                        },
                    },
                },
            },
        },
        "equivalent_but_different": {
            "type": "array",
            "description": (
                "Fields where the two providers express the same intent in "
                "different vocabulary, structure, or units, and which are "
                "therefore deliberately NOT findings. Populating this is part "
                "of the job: it is how a reviewer sees the comparison was "
                "semantic and not string equality."
            ),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["field", "akamai_value", "cloudflare_value", "why_equivalent"],
                "properties": {
                    "field": {"type": "string"},
                    "akamai_value": {"type": "string"},
                    "cloudflare_value": {"type": "string"},
                    "why_equivalent": {"type": "string"},
                },
            },
        },
        "not_comparable": {
            "type": "array",
            "description": (
                "Mapped fields only one provider can express, so no "
                "cross-comparison is possible. These are not drift: report "
                "them so the reviewer can see what the comparison could not "
                "cover."
            ),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["field", "reason"],
                "properties": {
                    "field": {"type": "string"},
                    "reason": {"type": "string", "enum": NOT_COMPARABLE_REASONS},
                    "note": {
                        "type": "string",
                        "description": (
                            "Only if the one-sided control carries real risk "
                            "for this domain -- e.g. a protection that exists "
                            "at one provider and has no counterpart at the "
                            "other, so traffic served by the other is "
                            "unprotected."
                        ),
                    },
                },
            },
        },
        "unmapped_observations": {
            "type": "array",
            "description": (
                "Provider configuration that looks materially risky but has no "
                "mapping entry, so it could not be compared. Gaps in the "
                "mapping are a finding about the mapping, not about the domain."
            ),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["provider", "provider_path", "observation"],
                "properties": {
                    "provider": {"type": "string", "enum": PROVIDERS},
                    "provider_path": {"type": "string"},
                    "observation": {"type": "string"},
                },
            },
        },
        "fields_reviewed": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "The ids of the mapping fields actually evaluated -- one plain "
                "string per field. Every field the mapping scopes to this "
                "domain must appear exactly once, whether it ended up as a "
                "finding, an equivalent_but_different entry, a not_comparable "
                "entry, or in agreement. An id missing from this array means "
                "the field was never examined."
            ),
        },
        "notes": {
            "type": "string",
            "description": (
                "Anything a reviewer needs that the fields above cannot carry: "
                "inputs that were missing, assumptions made, why the verdict "
                "is inconclusive, or why no human answer was obtained."
            ),
        },
    },
}
