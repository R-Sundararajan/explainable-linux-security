from typing import Any, Dict, List

from .validator import RAGResponseValidator
from .grounding import GroundingAnalyzer
from .formatter import ExplanationFormatter
from .guardrails import XAIGuardrails


class XAIEngine:

    VERSION = "1.0.0"

    def __init__(self):
        self.validator = RAGResponseValidator()

    def explain(
        self,
        rag_response: Dict[str, Any]
    ) -> Dict[str, Any]:

        validation_errors = self.validator.validate(
            rag_response
        )

        if validation_errors:
            raise ValueError(
                "Invalid RAGResponse:\n"
                + "\n".join(
                    f"- {error}"
                    for error in validation_errors
                )
            )

        grounding_analyzer = GroundingAnalyzer(
            rag_response
        )

        claims = self._process_claims(
            rag_response,
            grounding_analyzer
        )

        relationships = self._process_relationships(
            rag_response
        )

        alternatives = self._process_alternatives(
            rag_response
        )

        sources = self._process_sources(
            rag_response
        )

        grounding = self._process_grounding(
            rag_response,
            grounding_analyzer
        )

        result = {
            "schema_version":
                rag_response["schema_version"],

            "request_id":
                rag_response["request_id"],

            "event_id":
                rag_response["event_id"],

            "summary":
                self._get_summary(rag_response),

            "assessment":
                rag_response["assessment"],

            "claims":
                claims,

            "relationships":
                relationships,

            "alternative_explanations":
                alternatives,

            "unknowns":
                list(
                    rag_response.get(
                        "unknowns",
                        []
                    )
                ),

            "limitations":
                list(
                    rag_response.get(
                        "limitations",
                        []
                    )
                ),

            "recommendations":
                list(
                    rag_response.get(
                        "recommendations",
                        []
                    )
                ),

            "sources":
                sources,

            "grounding":
                grounding,

            "explanation_metadata": {
                "generator":
                    "deterministic_xai",

                "xai_version":
                    self.VERSION
            }
        }

        warnings = XAIGuardrails.validate_response(
            result
        )

        if warnings:
            result["grounding"][
                "semantic_warnings"
            ] = warnings

        return result

    def explain_text(
        self,
        rag_response: Dict[str, Any]
    ) -> str:

        result = self.explain(
            rag_response
        )

        return ExplanationFormatter.format(
            result
        )

    @staticmethod
    def _process_claims(
        rag_response: Dict[str, Any],
        grounding_analyzer: GroundingAnalyzer
    ) -> List[Dict[str, Any]]:

        output = []

        for claim in rag_response.get(
            "claims",
            []
        ):

            grounding = (
                grounding_analyzer.analyze_claim(
                    claim
                )
            )

            output.append({
                "claim_id":
                    claim["claim_id"],

                "statement":
                    claim["text"],

                "evidence_ids":
                    list(
                        claim.get(
                            "evidence_ids",
                            []
                        )
                    ),

                "knowledge_ids":
                    list(
                        claim.get(
                            "knowledge_ids",
                            []
                        )
                    ),

                "grounded":
                    grounding["grounded"]
                    and grounding["citation_valid"]
            })

        return output

    @staticmethod
    def _process_relationships(
        rag_response: Dict[str, Any]
    ) -> List[Dict[str, Any]]:

        return [
            {
                "relationship":
                    item["relationship"],

                "explanation":
                    item["explanation"],

                "evidence_ids":
                    list(
                        item.get(
                            "evidence_ids",
                            []
                        )
                    ),

                "knowledge_ids":
                    list(
                        item.get(
                            "knowledge_ids",
                            []
                        )
                    )
            }
            for item in rag_response.get(
                "security_relationships",
                []
            )
        ]

    @staticmethod
    def _process_alternatives(
        rag_response: Dict[str, Any]
    ) -> List[Dict[str, Any]]:

        return [
            {
                "explanation":
                    item["explanation"],

                "supporting_evidence_ids":
                    list(
                        item.get(
                            "supporting_evidence_ids",
                            []
                        )
                    )
            }
            for item in rag_response.get(
                "alternative_explanations",
                []
            )
        ]

    @staticmethod
    def _process_sources(
        rag_response: Dict[str, Any]
    ) -> List[Dict[str, Any]]:

        return [
            {
                "knowledge_id":
                    item["knowledge_id"],

                "source":
                    item.get("source"),

                "document_id":
                    item.get("document_id"),

                "title":
                    item.get("title"),

                "section":
                    item.get("section"),

                "url":
                    item.get("url")
            }
            for item in rag_response.get(
                "knowledge",
                []
            )
        ]

    @staticmethod
    def _process_grounding(
        rag_response: Dict[str, Any],
        grounding_analyzer: GroundingAnalyzer
    ) -> Dict[str, Any]:

        guardrails = rag_response.get(
            "guardrail_status",
            {}
        )

        calculated_grounding = (
            grounding_analyzer.overall_grounding()
        )

        warning = None

        if guardrails.get("grounded") is False:
            warning = (
                "The RAG layer reports that "
                "grounding is not valid."
            )

        elif not calculated_grounding:
            warning = (
                "One or more material claims "
                "could not be fully grounded."
            )

        elif guardrails.get(
            "citation_integrity"
        ) is False:
            warning = (
                "Citation integrity validation "
                "reported a problem."
            )

        elif guardrails.get(
            "schema_valid"
        ) is False:
            warning = (
                "The RAG layer reports that "
                "the response schema is invalid."
            )

        return {
            "declared_grounded":
                guardrails.get("grounded"),

            "calculated_grounded":
                calculated_grounding,

            "citation_integrity":
                guardrails.get(
                    "citation_integrity"
                ),

            "schema_valid":
                guardrails.get(
                    "schema_valid"
                ),

            "unsupported_claims":
                list(
                    guardrails.get(
                        "unsupported_claims",
                        []
                    )
                ),

            "warning":
                warning
        }

    @staticmethod
    def _get_summary(
        rag_response: Dict[str, Any]
    ) -> str:

        assessment = rag_response.get(
            "assessment"
        )

        if assessment is None:
            return (
                "No overall assessment was provided."
            )

        if isinstance(assessment, str):
            return assessment

        if isinstance(assessment, dict):

            if "summary" in assessment:
                return str(
                    assessment["summary"]
                )

            if "text" in assessment:
                return str(
                    assessment["text"]
                )

            if "status" in assessment:
                return str(
                    assessment["status"]
                )

        return str(assessment)