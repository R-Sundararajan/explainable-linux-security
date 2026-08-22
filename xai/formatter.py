from typing import Any, Dict


class ExplanationFormatter:

    @staticmethod
    def format(
        xai_response: Dict[str, Any]
    ) -> str:

        sections = []

        sections.append(
            "SECURITY ASSESSMENT\n"
            + str(
                xai_response.get(
                    "summary",
                    "No assessment available."
                )
            )
        )

        claims = xai_response.get("claims", [])

        if claims:

            text = "\n\nCLAIMS"

            for claim in claims:

                text += (
                    f"\n\n[{claim['claim_id']}] "
                    f"{claim['statement']}"
                )

                if claim["evidence_ids"]:
                    text += (
                        "\nEvidence: "
                        + ", ".join(
                            claim["evidence_ids"]
                        )
                    )

                if claim["knowledge_ids"]:
                    text += (
                        "\nKnowledge: "
                        + ", ".join(
                            claim["knowledge_ids"]
                        )
                    )

                text += (
                    "\nGrounded: "
                    + str(claim["grounded"])
                )

            sections.append(text)

        relationships = xai_response.get(
            "relationships",
            []
        )

        if relationships:

            text = "\n\nSECURITY RELATIONSHIPS"

            for item in relationships:
                text += (
                    f"\n\n{item['relationship']}"
                    f"\n{item['explanation']}"
                )

            sections.append(text)

        alternatives = xai_response.get(
            "alternative_explanations",
            []
        )

        if alternatives:

            text = "\n\nALTERNATIVE EXPLANATIONS"

            for item in alternatives:
                text += "\n- " + item["explanation"]

            sections.append(text)

        unknowns = xai_response.get("unknowns", [])

        if unknowns:

            text = "\n\nUNKNOWN"

            for item in unknowns:
                text += "\n- " + item

            sections.append(text)

        limitations = xai_response.get("limitations", [])

        if limitations:

            text = "\n\nLIMITATIONS"

            for item in limitations:
                text += "\n- " + item

            sections.append(text)

        recommendations = xai_response.get(
            "recommendations",
            []
        )

        if recommendations:

            text = "\n\nRECOMMENDATIONS"

            for item in recommendations:
                text += "\n- " + item

            sections.append(text)

        grounding = xai_response.get(
            "grounding",
            {}
        )

        warning = grounding.get("warning")

        if warning:
            sections.append(
                "\n\nXAI WARNING\n"
                + warning
            )

        return "\n".join(sections)