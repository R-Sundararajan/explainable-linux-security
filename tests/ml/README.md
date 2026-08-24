# Behavioral ML evaluation corpus

`build_dataset.sh` deterministically produces 60 labeled cases from 30 distinct
safe scenario families. Each family has two parameterized seeds. Families—not
individual observations—are assigned to train, validation, or final held-out
test partitions, so no family appears in more than one partition.

The corpus is synthetic structured evidence. It does not execute destructive or
credential-access operations. Path-bearing evidence, where required by the
strict evidence contract, refers only to generated `/tmp/linux-security-ml`
fixtures. Paths and process names are deliberately excluded from `ml_features_v1`.

Generated `dataset/` content is reproducible and ignored by Git. Run:

```bash
./tests/ml/build_dataset.sh
./tests/ml/train_models.sh
./tests/ml/evaluate.sh
```
