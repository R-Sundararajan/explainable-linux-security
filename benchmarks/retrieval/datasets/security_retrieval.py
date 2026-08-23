from __future__ import annotations

from security_reasoning.rag.evaluation.cases import (
    RetrievalCase,
    RetrievalCaseCategory,
)

DATASET_NAME = "security_retrieval"


def get_cases() -> tuple[RetrievalCase, ...]:
    return (
        # ========================================================
        # Exact terminology — C01-C03
        # ========================================================

        RetrievalCase(
            case_id="C01",
            query="privilege escalation",
            relevant_knowledge_ids=(
                "privilege-escalation-001",
                "privilege-escalation-002",
            ),
            category=RetrievalCaseCategory.EXACT,
        ),

        RetrievalCase(
            case_id="C02",
            query="network service scanning",
            relevant_knowledge_ids=(
                "network-discovery-001",
            ),
            category=RetrievalCaseCategory.EXACT,
        ),

        RetrievalCase(
            case_id="C03",
            query="file permissions",
            relevant_knowledge_ids=(
                "file-permissions-001",
            ),
            category=RetrievalCaseCategory.EXACT,
        ),

        # ========================================================
        # Paraphrase — C04-C07
        # ========================================================

        RetrievalCase(
            case_id="C04",
            query=(
                "How could an attacker obtain greater privileges "
                "than they currently have?"
            ),
            relevant_knowledge_ids=(
                "privilege-escalation-001",
                "privilege-escalation-002",
            ),
            category=RetrievalCaseCategory.PARAPHRASE,
        ),

        RetrievalCase(
            case_id="C05",
            query=(
                "What techniques could reveal services available "
                "on other machines?"
            ),
            relevant_knowledge_ids=(
                "network-discovery-001",
                "network-discovery-002",
            ),
            category=RetrievalCaseCategory.PARAPHRASE,
        ),

        RetrievalCase(
            case_id="C06",
            query=(
                "What determines whether a Linux user can read, "
                "modify, or execute a file?"
            ),
            relevant_knowledge_ids=(
                "file-permissions-001",
            ),
            category=RetrievalCaseCategory.PARAPHRASE,
        ),

        RetrievalCase(
            case_id="C07",
            query=(
                "Why might repeatedly creating processes that "
                "terminate almost immediately be suspicious?"
            ),
            relevant_knowledge_ids=(
                "short-lived-process-001",
                "process-lifecycle-001",
            ),
            category=RetrievalCaseCategory.PARAPHRASE,
        ),

        # ========================================================
        # Terminology mismatch — C08-C10
        # ========================================================

        RetrievalCase(
            case_id="C08",
            query=(
                "A program unexpectedly acquires administrator-level "
                "access. What security behavior does this represent?"
            ),
            relevant_knowledge_ids=(
                "privilege-escalation-001",
                "privilege-escalation-002",
            ),
            category=RetrievalCaseCategory.TERMINOLOGY_MISMATCH,
        ),

        RetrievalCase(
            case_id="C09",
            query=(
                "A process is probing reachable hosts to learn what "
                "services are exposed. What knowledge is relevant?"
            ),
            relevant_knowledge_ids=(
                "network-discovery-001",
                "network-discovery-002",
            ),
            category=RetrievalCaseCategory.TERMINOLOGY_MISMATCH,
        ),

        RetrievalCase(
            case_id="C10",
            query=(
                "A process is consuming an unusually large amount "
                "of processor capacity for an extended period."
            ),
            relevant_knowledge_ids=(
                "resource-abuse-001",
                "resource-abuse-002",
            ),
            category=RetrievalCaseCategory.TERMINOLOGY_MISMATCH,
        ),

        # ========================================================
        # Near-miss retrieval — C11-C13
        # ========================================================

        RetrievalCase(
            case_id="C11",
            query=(
                "Which knowledge explains obtaining elevated "
                "permissions rather than ordinary process execution?"
            ),
            relevant_knowledge_ids=(
                "privilege-escalation-001",
                "privilege-escalation-002",
            ),
            category=RetrievalCaseCategory.NEAR_MISS,
        ),

        RetrievalCase(
            case_id="C12",
            query=(
                "Which knowledge concerns discovering network services "
                "rather than simply maintaining network connections?"
            ),
            relevant_knowledge_ids=(
                "network-discovery-001",
                "network-discovery-002",
            ),
            category=RetrievalCaseCategory.NEAR_MISS,
        ),

        RetrievalCase(
            case_id="C13",
            query=(
                "Which knowledge explains unusually high CPU usage "
                "rather than general process scheduling?"
            ),
            relevant_knowledge_ids=(
                "resource-abuse-001",
                "resource-abuse-002",
            ),
            category=RetrievalCaseCategory.NEAR_MISS,
        ),

        # ========================================================
        # Multi-relevant — C14-C16
        # ========================================================

        RetrievalCase(
            case_id="C14",
            query=(
                "What security knowledge is relevant to a process "
                "that repeatedly starts and terminates quickly?"
            ),
            relevant_knowledge_ids=(
                "process-lifecycle-001",
                "short-lived-process-001",
            ),
            category=RetrievalCaseCategory.MULTI_RELEVANT,
        ),

        RetrievalCase(
            case_id="C15",
            query=(
                "What knowledge applies when an attacker tries to "
                "gain higher permissions using elevation mechanisms?"
            ),
            relevant_knowledge_ids=(
                "privilege-escalation-001",
                "privilege-escalation-002",
            ),
            category=RetrievalCaseCategory.MULTI_RELEVANT,
        ),

        RetrievalCase(
            case_id="C16",
            query=(
                "What knowledge is relevant to understanding both "
                "network discovery and system network configuration?"
            ),
            relevant_knowledge_ids=(
                "network-discovery-001",
                "network-discovery-002",
            ),
            category=RetrievalCaseCategory.MULTI_RELEVANT,
        ),

        # ========================================================
        # Multi-concept — C17-C18
        # ========================================================

        RetrievalCase(
            case_id="C17",
            query=(
                "A suspicious process repeatedly starts, consumes "
                "significant CPU, and terminates quickly. What "
                "knowledge should be considered?"
            ),
            relevant_knowledge_ids=(
                "process-lifecycle-001",
                "short-lived-process-001",
                "resource-abuse-001",
                "resource-abuse-002",
            ),
            category=RetrievalCaseCategory.MULTI_CONCEPT,
        ),

        RetrievalCase(
            case_id="C18",
            query=(
                "An attacker appears to obtain elevated privileges "
                "and then interact with protected files. What "
                "knowledge is relevant?"
            ),
            relevant_knowledge_ids=(
                "privilege-escalation-001",
                "privilege-escalation-002",
                "file-permissions-001",
                "file-write-001",
            ),
            category=RetrievalCaseCategory.MULTI_CONCEPT,
        ),

        # ========================================================
        # No-answer / insufficient knowledge — C19-C20
        # ========================================================

        RetrievalCase(
            case_id="C19",
            query=(
                "How does Linux configure firewall rules using nftables?"
            ),
            relevant_knowledge_ids=(),
            category=RetrievalCaseCategory.NO_ANSWER,
        ),

        RetrievalCase(
            case_id="C20",
            query=(
                "How does SELinux enforce mandatory access control "
                "through security contexts?"
            ),
            relevant_knowledge_ids=(),
            category=RetrievalCaseCategory.NO_ANSWER,
        ),
    )