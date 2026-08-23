# R10 Embedding Model Selection Benchmark

## Purpose

This document records the evaluation process used to select the embedding model for the local semantic retrieval component of the RAG system.

The objective was not to identify a universally best embedding model. The objective was to select the model that performs best for this project's security-knowledge retrieval workload under the same controlled benchmark conditions.

## 1. Models Evaluated

1. `sentence-transformers/all-MiniLM-L6-v2`
2. `intfloat/e5-small-v2`
3. `BAAI/bge-small-en-v1.5`

All candidates used the same retrieval pipeline and benchmark dataset.

## 2. Benchmark Dataset

Dataset: `security_retrieval`

Size: **20 evaluation cases**

Categories:

- Exact terminology
- Paraphrase
- Terminology mismatch
- Near-miss retrieval
- Multi-relevant
- Multi-concept
- No-answer / insufficient knowledge

The dataset includes two explicit no-answer cases:

- C19 — nftables
- C20 — SELinux

These concepts are intentionally absent from the benchmark knowledge corpus.

## 3. Retrieval Architecture Under Test

```text
Security Knowledge Corpus
        |
        v
Semantic chunk embeddings
        |
        v
FAISS vector index
        |
        v
Query embedding
        |
        v
Cosine-similarity search
        |
        v
Ranked RetrievalResult list
        |
        v
Evaluation metrics
```

The embedding model was the principal variable. The corpus, FAISS retrieval mechanism, query cases, K values, and evaluation metrics were held constant.

## 4. Evaluation Procedure

For every candidate model:

1. Load the model locally.
2. Embed the security knowledge corpus.
3. Build the FAISS vector index.
4. Execute all 20 benchmark queries.
5. Retrieve top `K` results for `K = 1, 3, 5`.
6. Calculate Hit@K, Recall@K, Precision@K, and MRR.
7. Calculate metrics independently by benchmark category.
8. Evaluate no-answer behavior using score-threshold calibration.
9. Serialize the complete results for comparison.

## 5. Aggregate Results

### K = 1

| Model | Hit@1 | Recall@1 | Precision@1 | MRR |
|---|---:|---:|---:|---:|
| `all-MiniLM-L6-v2` | **0.9000** | 0.5000 | **0.9000** | **0.9000** |
| `e5-small-v2` | **0.9000** | 0.5000 | **0.9000** | **0.9000** |
| `bge-small-en-v1.5` | 0.8000 | 0.4250 | 0.8000 | 0.8000 |

MiniLM and E5 tied for the strongest top-1 performance. BGE was weaker.

### K = 3

| Model | Hit@3 | Recall@3 | Precision@3 | MRR |
|---|---:|---:|---:|---:|
| `all-MiniLM-L6-v2` | **0.9000** | **0.8750** | **0.5833** | **0.9000** |
| `e5-small-v2` | **0.9000** | 0.8375 | 0.5500 | **0.9000** |
| `bge-small-en-v1.5` | **0.9000** | 0.7875 | 0.5167 | 0.8417 |

MiniLM achieved the strongest Recall@3 and Precision@3.

### K = 5

| Model | Hit@5 | Recall@5 | Precision@5 | MRR |
|---|---:|---:|---:|---:|
| `all-MiniLM-L6-v2` | **0.9000** | **0.9000** | **0.3700** | **0.9000** |
| `e5-small-v2` | **0.9000** | 0.8875 | 0.3600 | **0.9000** |
| `bge-small-en-v1.5` | **0.9000** | **0.9000** | **0.3700** | 0.8417 |

MiniLM and BGE tied for Recall@5 and Precision@5, while MiniLM retained the stronger MRR.

## 6. Category-Level Evaluation

At K=3, Recall was:

| Category | MiniLM | E5 | BGE |
|---|---:|---:|---:|
| Exact | **1.0000** | **1.0000** | **1.0000** |
| Paraphrase | **1.0000** | **1.0000** | **1.0000** |
| Terminology mismatch | **1.0000** | 0.8333 | 0.8333 |
| Near-miss | **1.0000** | **1.0000** | **1.0000** |
| Multi-relevant | **1.0000** | **1.0000** | 0.8333 |
| Multi-concept | **0.7500** | 0.6250 | 0.6250 |

The category analysis reinforced the aggregate result: MiniLM showed the strongest overall retrieval behavior on this benchmark.

## 7. No-Answer / Abstention Evaluation

Normal retrieval metrics cannot meaningfully evaluate C19/C20 because those cases intentionally have no relevant knowledge IDs.

A separate score-threshold evaluation was therefore performed:

1. Obtain the strongest retrieval score for each query.
2. Separate answerable and no-answer cases.
3. Generate candidate score thresholds.
4. Select the threshold producing the highest benchmark classification accuracy.
5. Classify a query as abstaining when its strongest retrieval score is below the threshold.

### Results

| Model | Calibrated Threshold | Abstention Accuracy |
|---|---:|---:|
| `all-MiniLM-L6-v2` | **0.493929** | **1.00** |
| `bge-small-en-v1.5` | 0.699555 | 0.95 |
| `e5-small-v2` | 0.822779 | 0.90 |

MiniLM correctly separated the benchmark's answerable and no-answer cases under this calibration procedure.

### Important limitation

Thresholds are model-specific. A MiniLM score of `0.493929` is not numerically interchangeable with an E5 or BGE score because each embedding model has its own score distribution.

The benchmark contains only two no-answer cases, so this calibration is evidence for this project benchmark, not proof that the threshold generalizes to arbitrary security queries.

## 8. Selection Decision

### Selected model

```text
sentence-transformers/all-MiniLM-L6-v2
```

### Rationale

MiniLM provided the strongest overall balance of:

- Top-1 retrieval quality
- Top-3 recall
- Top-3 precision
- Top-5 recall
- Ranking quality
- Category-level robustness
- No-answer abstention behavior

Key results:

```text
Hit@1       = 0.9000
MRR@1       = 0.9000

Hit@3       = 0.9000
Recall@3    = 0.8750
Precision@3 = 0.5833
MRR@3       = 0.9000

Hit@5       = 0.9000
Recall@5    = 0.9000
Precision@5 = 0.3700
MRR@5       = 0.9000
```

It also achieved `1.00` abstention accuracy on the current no-answer benchmark.

## 9. Interpretation

The defensible statement is:

> `sentence-transformers/all-MiniLM-L6-v2` was selected as the embedding model for the current RAG implementation because it achieved the strongest overall retrieval and abstention performance on the project's 20-case security retrieval benchmark among the evaluated candidates.

This should not be stated as:

> MiniLM is the best embedding model.

The benchmark is project-specific and relatively small. Its purpose is engineering model selection for this RAG system, not general-purpose evaluation of embedding models.

## 10. Reproducibility

Run:

```bash
python -m benchmarks.retrieval.run_embedding_benchmark
```

The generated result contains:

```text
aggregate
categories
abstention
```

for every candidate model.

## 11. Final Decision

```text
Selected semantic embedding model:

sentence-transformers/all-MiniLM-L6-v2

MODEL SELECTION: COMPLETE
```

The selected model can now be used as the default embedding model for semantic retrieval. The other evaluated models remain useful as benchmark references.
