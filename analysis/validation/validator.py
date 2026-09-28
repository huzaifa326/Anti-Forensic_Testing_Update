"""
Simple validation module to compare processed outputs against a ground-truth dataset.
Provides a basic record-level validation and summary report.
"""
import os
import json
from typing import Dict, Any

from config.settings import PROCESSED_DIR


def load_ground_truth(dataset_name: str, datasets_dir: str = None) -> list:
    """Load a ground-truth dataset (JSON array of records).
    Expects datasets to live in `storage/processed/datasets/` or provided dir.
    """
    if datasets_dir is None:
        datasets_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'storage', 'processed', 'datasets')
    path = os.path.join(datasets_dir, dataset_name)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Dataset not found: {path}")
    with open(path, 'r') as f:
        return json.load(f)


def validate_case_against_dataset(case_id: str, dataset_file: str) -> Dict[str, Any]:
    """Compare normalized logs for `case_id` with ground-truth dataset.
    Returns a summary dict with counts and a small sample of mismatches.
    """
    norm_path = os.path.join(PROCESSED_DIR, 'normalized_logs.json')
    if not os.path.isfile(norm_path):
        raise FileNotFoundError("Normalized logs not found. Run parsing first.")

    with open(norm_path, 'r') as f:
        data = json.load(f)
    records = data.get('records', [])

    gt = load_ground_truth(dataset_file)

    # Simple validation: compare counts and sample record equality by index
    result = {
        'case_id': case_id,
        'expected_count': len(gt),
        'observed_count': len(records),
        'matches': 0,
        'mismatches_sample': [],
    }

    for i, r in enumerate(gt):
        if i < len(records) and records[i].get('raw_message') == r.get('raw_message'):
            result['matches'] += 1
        else:
            if len(result['mismatches_sample']) < 10:
                result['mismatches_sample'].append({'index': i, 'expected': r, 'observed': records[i] if i < len(records) else None})

    return result
"""Validation utilities to compare detected alerts to ground-truth datasets.

The module looks for a ground truth JSON file in `storage/processed/ground_truth/{case_id}.json`
with structure: { "alerts": [ {"alert_type": "timestomping", "description": "..."}, ... ] }

It returns basic counts and a simple match metric (how many alerts matched by type).
"""
import os
import json
from typing import Dict

from database.db_setup import get_alerts_for_case


def validate_case_against_dataset(case_id: str, dataset_path: str = None) -> Dict:
    if dataset_path is None:
        dataset_path = os.path.join(os.getcwd(), "storage", "processed", "ground_truth", f"{case_id}.json")

    if not os.path.isfile(dataset_path):
        return {"status": "error", "message": f"Ground truth file not found: {dataset_path}"}

    with open(dataset_path, 'r') as f:
        gt = json.load(f)

    gt_alerts = gt.get('alerts', [])
    detected = get_alerts_for_case(case_id)

    # Simple matching by alert_type
    gt_types = [a.get('alert_type') for a in gt_alerts]
    det_types = [d.get('alert_type') for d in detected]

    matched = 0
    for t in gt_types:
        if t in det_types:
            matched += 1

    total_gt = len(gt_types)
    total_det = len(det_types)

    score = matched / total_gt if total_gt else 0.0

    return {
        "status": "success",
        "matched": matched,
        "ground_truth_total": total_gt,
        "detected_total": total_det,
        "score": score,
        "message": f"Matched {matched}/{total_gt} ground-truth alerts."
    }
