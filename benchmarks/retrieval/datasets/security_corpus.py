from __future__ import annotations

from security_reasoning.knowledge.models import KnowledgeChunk


CORPUS_NAME = "security_corpus"


def get_corpus() -> tuple[KnowledgeChunk, ...]:
    return (
        # --------------------------------------------------------
        # Privilege escalation
        # --------------------------------------------------------

        KnowledgeChunk(
            knowledge_id="privilege-escalation-001",
            document_id="security-knowledge-001",
            source_id="mitre_attack",
            title="Privilege Escalation",
            content=(
                "Adversaries may attempt to gain higher-level permissions "
                "on a system through privilege escalation techniques."
            ),
            chunk_index=0,
        ),

        KnowledgeChunk(
            knowledge_id="privilege-escalation-002",
            document_id="security-knowledge-001",
            source_id="mitre_attack",
            title="Abuse Elevation Control Mechanism",
            content=(
                "An adversary may abuse mechanisms that control elevation "
                "of privileges in order to execute actions with higher "
                "permissions."
            ),
            chunk_index=1,
        ),

        # --------------------------------------------------------
        # Network activity
        # --------------------------------------------------------

        KnowledgeChunk(
            knowledge_id="network-discovery-001",
            document_id="security-knowledge-002",
            source_id="mitre_attack",
            title="Network Service Scanning",
            content=(
                "Adversaries may gather information about network services "
                "and accessible systems to support subsequent operations."
            ),
            chunk_index=0,
        ),

        KnowledgeChunk(
            knowledge_id="network-discovery-002",
            document_id="security-knowledge-002",
            source_id="mitre_attack",
            title="System Network Configuration Discovery",
            content=(
                "Adversaries may look for information about network "
                "configuration, interfaces, routes, and connected systems."
            ),
            chunk_index=1,
        ),

        KnowledgeChunk(
            knowledge_id="network-connection-001",
            document_id="security-knowledge-003",
            source_id="linux_security",
            title="Network Connections",
            content=(
                "Linux systems maintain network connections between "
                "processes and remote endpoints."
            ),
            chunk_index=0,
        ),

        # --------------------------------------------------------
        # File activity
        # --------------------------------------------------------

        KnowledgeChunk(
            knowledge_id="file-permissions-001",
            document_id="security-knowledge-004",
            source_id="securing_debian",
            title="File Permissions",
            content=(
                "Unix file permissions determine which users may read, "
                "write, or execute a file."
            ),
            chunk_index=0,
        ),

        KnowledgeChunk(
            knowledge_id="file-write-001",
            document_id="security-knowledge-005",
            source_id="linux_security",
            title="File Modification",
            content=(
                "A process may modify files when its effective permissions "
                "allow write access to the target."
            ),
            chunk_index=0,
        ),

        KnowledgeChunk(
            knowledge_id="file-delete-001",
            document_id="security-knowledge-005",
            source_id="linux_security",
            title="File Deletion",
            content=(
                "Processes with appropriate permissions may remove files "
                "from the filesystem."
            ),
            chunk_index=1,
        ),

        # --------------------------------------------------------
        # Process behavior
        # --------------------------------------------------------

        KnowledgeChunk(
            knowledge_id="process-management-001",
            document_id="security-knowledge-006",
            source_id="linux_security",
            title="Process Management",
            content=(
                "Linux processes have identities and execution contexts "
                "that determine how they interact with system resources."
            ),
            chunk_index=0,
        ),

        KnowledgeChunk(
            knowledge_id="process-lifecycle-001",
            document_id="security-knowledge-006",
            source_id="linux_security",
            title="Process Lifecycle",
            content=(
                "Processes are created, execute within a process context, "
                "and eventually terminate."
            ),
            chunk_index=1,
        ),

        KnowledgeChunk(
            knowledge_id="short-lived-process-001",
            document_id="security-knowledge-007",
            source_id="linux_security",
            title="Short-Lived Processes",
            content=(
                "Repeated creation of processes that terminate quickly "
                "may indicate automated or transient activity."
            ),
            chunk_index=0,
        ),

        # --------------------------------------------------------
        # Persistence
        # --------------------------------------------------------

        KnowledgeChunk(
            knowledge_id="persistence-001",
            document_id="security-knowledge-008",
            source_id="mitre_attack",
            title="Persistence",
            content=(
                "Adversaries may establish mechanisms that allow them "
                "to maintain access to a system across interruptions "
                "or reboots."
            ),
            chunk_index=0,
        ),

        KnowledgeChunk(
            knowledge_id="persistence-startup-001",
            document_id="security-knowledge-008",
            source_id="mitre_attack",
            title="Startup Persistence",
            content=(
                "Startup mechanisms can be abused to execute malicious "
                "programs automatically when a system starts."
            ),
            chunk_index=1,
        ),

        # --------------------------------------------------------
        # Credential activity
        # --------------------------------------------------------

        KnowledgeChunk(
            knowledge_id="credential-access-001",
            document_id="security-knowledge-009",
            source_id="mitre_attack",
            title="Credential Access",
            content=(
                "Adversaries may attempt to obtain credentials or "
                "authentication material from systems."
            ),
            chunk_index=0,
        ),

        # --------------------------------------------------------
        # Resource abuse
        # --------------------------------------------------------

        KnowledgeChunk(
            knowledge_id="resource-abuse-001",
            document_id="security-knowledge-010",
            source_id="linux_security",
            title="Resource Consumption",
            content=(
                "Processes can consume CPU, memory, and I/O resources "
                "during normal or abnormal system activity."
            ),
            chunk_index=0,
        ),

        KnowledgeChunk(
            knowledge_id="resource-abuse-002",
            document_id="security-knowledge-010",
            source_id="linux_security",
            title="Sustained CPU Activity",
            content=(
                "Sustained high CPU utilization may indicate computationally "
                "intensive workloads or resource-abusing processes."
            ),
            chunk_index=1,
        ),

        # --------------------------------------------------------
        # Telemetry quality
        # --------------------------------------------------------

        KnowledgeChunk(
            knowledge_id="telemetry-quality-001",
            document_id="security-knowledge-011",
            source_id="linux_security",
            title="Telemetry Coverage",
            content=(
                "Incomplete telemetry can reduce confidence in conclusions "
                "drawn from observed system activity."
            ),
            chunk_index=0,
        ),

        # --------------------------------------------------------
        # Unrelated / distractor knowledge
        # --------------------------------------------------------

        KnowledgeChunk(
            knowledge_id="unrelated-filesystem-001",
            document_id="security-knowledge-012",
            source_id="linux_security",
            title="Filesystem Layout",
            content=(
                "Linux filesystems organize files and directories "
                "according to filesystem hierarchy conventions."
            ),
            chunk_index=0,
        ),

        KnowledgeChunk(
            knowledge_id="unrelated-process-scheduling-001",
            document_id="security-knowledge-013",
            source_id="linux_security",
            title="Process Scheduling",
            content=(
                "The Linux scheduler determines when runnable processes "
                "receive CPU execution time."
            ),
            chunk_index=0,
        ),
    )