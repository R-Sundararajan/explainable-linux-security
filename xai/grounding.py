from typing import Any, Dict, List, Set


class GroundingAnalyzer:

    def __init__(self, rag_response: Dict[str, Any]):
        self.rag_response = rag_response

        self.knowledge_ids: Set[str] = {
            item.get("knowledge_id")
            for item in rag_response.get("knowledge", [])
            if item.get("knowledge_id")
        }

    def analyze_claim(
        self,
        claim: Dict[str, Any]
    ) -> Dict[str, Any]:

        evidence_ids = claim.get("evidence_ids", [])
        knowledge_ids = claim.get("knowledge_ids", [])

        has_support = bool(
            evidence_ids or knowledge_ids
        )

        invalid_knowledge_ids = [
            knowledge_id
            for knowledge_id in knowledge_ids
            if knowledge_id not in self.knowledge_ids
        ]

        citation_valid = not invalid_knowledge_ids

        return {
            "claim_id": claim.get("claim_id"),
            "grounded": has_support,
            "citation_valid": citation_valid,
            "evidence_ids": evidence_ids,
            "knowledge_ids": knowledge_ids,
            "invalid_knowledge_ids": invalid_knowledge_ids,
        }

    def analyze_claims(self) -> List[Dict[str, Any]]:

        return [
            self.analyze_claim(claim)
            for claim in self.rag_response.get("claims", [])
        ]

    def overall_grounding(self) -> bool:

        results = self.analyze_claims()

        if not results:
            return True

        return all(
            result["grounded"] and result["citation_valid"]
            for result in results
        )