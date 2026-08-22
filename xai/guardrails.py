from typing import Any, Dict, List


class XAIGuardrails:

    @staticmethod
    def validate_response(
        response: Dict[str, Any]
    ) -> List[str]:

        warnings = []

        grounding = response.get("grounding", {})

        if grounding.get("calculated_grounded") is False:
            warnings.append(
                "One or more material claims could not be fully grounded."
            )

        if grounding.get("citation_integrity") is False:
            warnings.append(
                "Citation integrity validation reported a problem."
            )

        if grounding.get("schema_valid") is False:
            warnings.append(
                "The RAG response was reported as schema-invalid."
            )

        unsupported = grounding.get(
            "unsupported_claims",
            []
        )

        if unsupported:
            warnings.append(
                "Unsupported claims were reported: "
                + ", ".join(unsupported)
            )

        return warnings