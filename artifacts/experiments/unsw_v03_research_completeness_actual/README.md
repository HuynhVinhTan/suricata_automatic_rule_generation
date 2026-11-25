# UNSW-NB15 V03 research completeness — actual run

Status: `COMPLETED` from the verified raw training hard link. Official Test was not opened by V03.

## Data and preprocessing

- Raw SHA256: `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa`
- Raw rows: `175341`; processed rows: `143229`; removed: `32112`
- Removal reason: unsupported protocol only (`32112`); NaN, Inf, negative and invalid-label rows: `0`
- Exact raw duplicate rows: `0`; duplicate four-feature rows reported, not removed: `68352`
- V02 Development/Validation/Calibration: `102305 / 20462 / 20462`
- V02 feature-group overlap across partitions: `0`

## V03 five-fold OOF CV

Values are mean ± sample standard deviation across five folds. Thresholds are 0.5 for supervised families and Normal-only 1% FPR calibration for AE.

| Family | Accuracy | Precision | Recall | F1 | AP | FPR |
|---|---:|---:|---:|---:|---:|---:|
| LogReg | 0.733678 ± 0.049846 | 0.778480 ± 0.008314 | 0.805550 ± 0.096503 | 0.789958 ± 0.047092 | 0.846744 ± 0.052750 | 0.388523 ± 0.032034 |
| RF | 0.918322 ± 0.022013 | 0.922159 ± 0.016421 | 0.950650 ± 0.025650 | 0.936058 ± 0.017320 | 0.985581 ± 0.007842 | 0.136643 ± 0.030239 |
| MLP | 0.887278 ± 0.029111 | 0.899737 ± 0.012505 | 0.923779 ± 0.039972 | 0.911364 ± 0.023755 | 0.965033 ± 0.017200 | 0.174784 ± 0.020856 |
| AE | 0.381878 ± 0.007736 | 0.714133 ± 0.214751 | 0.026266 ± 0.015347 | 0.050372 ± 0.028852 | 0.685286 ± 0.042981 | 0.013488 ± 0.009444 |

All 20 fold rows are in `cv_fold_metrics.csv`; the machine-readable summary is `cv_summary.csv`.

## Figures and provenance

- EDA: `figures/eda/`
- Evaluation: `figures/evaluation/`
- Training histories: `training_history.json`
- Checkpoint SHA256 values: `manifest.json` → `checkpoint_sha256`
- Frozen V02 model hashes: `manifest.json` → `v02_frozen_model_hashes`
- Leakage audit: `leakage_audit.json`
- Quality audit: `data_quality_audit.json`

The V03 results are Development-only cross-validation evidence. They must not be combined with or described as the frozen V02 Official Test result.
