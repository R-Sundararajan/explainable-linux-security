from __future__ import annotations

from security_reasoning.knowledge.models import KnowledgeChunk

def security_corpus() -> list[KnowledgeChunk]:
    return [
        KnowledgeChunk(
            knowledge_id="mitre-privilege-escalation-001",
            document_id="mitre-attack",
            source_id="mitre_attack",
            title="Privilege Escalation",
            content=(
                "Adversaries may attempt to gain higher-level permissions "
                "on a system through privilege escalation techniques."
            ),
            chunk_index=0,
        ),
        KnowledgeChunk(
            knowledge_id="mitre-network-service-001",
            document_id="mitre-attack",
            source_id="mitre_attack",
            title="Network Service Scanning",
            content=(
                "Adversaries may gather information about network services "
                "and accessible systems to support subsequent operations."
            ),
            chunk_index=1,
        ),
        KnowledgeChunk(
            knowledge_id="linux-file-permissions-001",
            document_id="linux-security",
            source_id="securing_debian",
            title="File Permissions",
            content=(
                "Unix file permissions determine which users may read, "
                "write, or execute a file."
            ),
            chunk_index=0,
        ),
        KnowledgeChunk(
            knowledge_id="linux-process-001",
            document_id="linux-security",
            source_id="securing_debian",
            title="Process Management",
            content=(
                "Linux processes have identities and execution contexts "
                "that determine how they interact with system resources."
            ),
            chunk_index=1,
        ),
    ]