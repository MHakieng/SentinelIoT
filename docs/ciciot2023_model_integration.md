# CICIoT2023 Model Integration

This integration prepares an offline CICIoT2023 validation path and a live
inference path for Sentinel-IoT. Offline validation metrics are not runtime/live
detection metrics.

## Dataset

- Dataset: CICIoT2023 CSV files
- Expected input: a directory containing one or more `.csv` files
- Training script: `sentinel_iot/ml/train_ciciot2023_random_forest.py`

## Selected Columns

Only columns that can be mapped to the current live-flow contract are used:

| CICIoT2023 column | Sentinel-IoT feature |
| --- | --- |
| `Number` | `packet_count` |
| `Tot sum` | `byte_count` |
| `AVG` | `avg_packet_size` |
| `IAT` | `mean_iat` |
| `Variance` | `var_iat` |
| `Rate` | `packet_rate` |

The fixed runtime feature order is stored in `sentinel_iot/ml/live_feature_schema.py`.
`flow_duration` was not present in the downloaded CSV files, so no synthetic
duration value is created. Live inference derives `packet_rate` from captured
flow duration as `packet_count / duration`, or `0.0` when duration is not
positive.

## Label Mapping

Binary classification is used in the first stage:

- `BenignTraffic` -> `0`
- every other label -> `1`

The downloaded CSV files did not include an in-file `label` column. Labels were
inferred from the file path/name: paths containing `BenignTraffic` are benign;
all other files are attack traffic.

## Model

The main model is `RandomForestClassifier` inside a scikit-learn pipeline:

- `SimpleImputer(strategy="median")`
- `RandomForestClassifier(n_estimators=200, class_weight="balanced", n_jobs=-1)`

RandomForest does not require a scaler, so the final CICIoT2023 pipeline omits
feature scaling.

## Why Only 6 Features?

The live monitor produces the same six packet-flow features used by the trained
model. Using only matching CICIoT2023 columns prevents training on features that
runtime inference cannot produce.

## Outputs

Default model artifact:

```text
sentinel_iot/ml/models/ciciot2023_random_forest.joblib
```

Default offline validation report:

```text
evaluation/results/ciciot2023_random_forest_report.json
```

The report contains only metrics computed from the real test split:

- precision
- recall
- f1-score
- accuracy
- confusion matrix
- classification report
- feature importances

## Usage

```powershell
python -m sentinel_iot.ml.train_ciciot2023_random_forest `
  --data-dir C:\path\to\CICIoT2023\CSV `
  --max-benign 300000 `
  --max-attack 300000
```

If the dataset directory or required columns are missing, the script exits with a clear error.

## Scope Boundary

Offline CICIoT2023 validation metrics are dataset validation metrics. They are not runtime/live detection TP/FP/F1 metrics. Runtime metrics require separately labelled live traffic.

## Live Inference

Live flow dictionaries are converted to the exact `LIVE_FEATURE_SCHEMA` order
before prediction:

```text
packet_count, byte_count, avg_packet_size, mean_iat, var_iat, packet_rate
```

If the RandomForest artifact is missing, inference returns an honest unavailable
response instead of crashing.
