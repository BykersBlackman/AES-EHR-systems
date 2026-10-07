"""
DEPRECATED. EHR record generation now lives in synthetic_data.py, which produces
a single correlated dataset (staff, patients and records that link together) and
writes all three CSV extracts in one place.

This shim remains so existing references keep working: running it regenerates the
correct, correlated CSVs instead of the old stand-alone (uncorrelated) data.
"""

from synthetic_data import build_dataset, write_csv_extracts

if __name__ == "__main__":
    staff_members, patients, synthetic_records = build_dataset()
    write_csv_extracts(staff_members, patients, synthetic_records)
    print("Regenerated correlated CSV extracts via synthetic_data.py.")
