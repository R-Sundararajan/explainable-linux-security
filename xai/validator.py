from typing import Any, Dict, List


class RAGResponseValidator:

    REQUIRED_FIELDS = {
        "schema_version",
        "request_id",
        "event_id",
        "assessment",
        "claims",
        "security_relationships",
        "alternative_explanations",
        "unknowns",
        "recommendations",
        "knowledge",
        "limitations",
        "guardrail_status",
    }

    CLAIM_FIELDS = {
        "claim_id",
        "text",
        "evidence_ids",
        "knowledge_ids",
    }

    RELATIONSHIP_FIELDS = {
        "relationship",
        "explanation",
        "evidence_ids",
        "knowledge_ids",
    }

    ALTERNATIVE_FIELDS = {
        "explanation",
        "supporting_evidence_ids",
    }

    KNOWLEDGE_FIELDS = {
        "knowledge_id",
    }

    def validate(self, response: Dict[str, Any]) -> List[str]:

        errors = []

        if not isinstance(response, dict):
            return ["RAGResponse must be a dictionary."]

        missing = self.REQUIRED_FIELDS - set(response.keys())

        for field in sorted(missing):
            errors.append(
                f"Missing required field: {field}"
            )

        self._validate_list(
            response,
            "claims",
            self.CLAIM_FIELDS,
            errors
        )

        self._validate_list(
            response,
            "security_relationships",
            self.RELATIONSHIP_FIELDS,
            errors
        )

        self._validate_list(
            response,
            "alternative_explanations",
            self.ALTERNATIVE_FIELDS,
            errors
        )

        self._validate_list(
            response,
            "knowledge",
            self.KNOWLEDGE_FIELDS,
            errors
        )

        if "guardrail_status" in response:
            if not isinstance(response["guardrail_status"], dict):
                errors.append(
                    "guardrail_status must be a dictionary."
                )

        return errors

    @staticmethod
    def _validate_list(
        response: Dict[str, Any],
        field_name: str,
        required_fields: set,
        errors: List[str]
    ):

        if field_name not in response:
            return

        value = response[field_name]

        if not isinstance(value, list):
            errors.append(
                f"{field_name} must be a list."
            )
            return

        for index, item in enumerate(value):

            if not isinstance(item, dict):
                errors.append(
                    f"{field_name}[{index}] must be a dictionary."
                )
                continue

            missing = required_fields - set(item.keys())

            for field in sorted(missing):
                errors.append(
                    f"{field_name}[{index}] missing field: {field}"
                )