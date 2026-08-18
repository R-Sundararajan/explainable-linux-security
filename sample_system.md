Workflow:

┌─────────────────────────────────────────────┐
│                 LINUX HOST                  │
│                                             │
│  eBPF        /proc       process context    │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│             TELEMETRY COLLECTOR             │
│                                             │
│  Raw observation → 5-second aggregation     │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│             FEATURE ENGINEERING             │
│                                             │
│  Raw telemetry → semantic feature vector    │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│             ANOMALY DETECTION               │
│                                             │
│  Baseline → deviation → anomaly score       │
└──────────────────────┬──────────────────────┘
                       │
                 anomaly threshold
                       │
                       ▼
┌─────────────────────────────────────────────┐
│                  EVIDENCE                   │
│                                             │
│  Observed + expected + deviation + context  │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│         SECURITY REASONING LAYER            │
│                                             │
│  Evidence                                   │
│      │                                      │
│      ├──────► Knowledge Retrieval (RAG)     │
│      │                │                     │
│      │                ▼                     │
│      │        Relevant security knowledge   │
│      │                │                     │
│      └────────────────┤                     │
│                       ▼                     │
│                 Ollama / vLLM               │
│                       │                     │
│                       ▼                     │
│              Contextual reasoning           │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│                  RISK / XAI                 │
│                                             │
│  Risk + confidence + explanation            │
│  Observed / inferred / known / unknown      │
│  Recommendation                             │
└─────────────────────────────────────────────┘