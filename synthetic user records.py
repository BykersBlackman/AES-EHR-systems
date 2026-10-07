"""
DEPRECATED. User/staff generation now lives in synthetic_data.py, where staff are
part of one correlated dataset (each clinical staff member belongs to a department
and is linked to the patients and records they are responsible for).

This shim remains so existing references keep working: running it regenerates the
correct, correlated CSV extracts instead of the old stand-alone user data.
"""

from synthetic_data import build_dataset, write_csv_extracts

if __name__ == "__main__":
    staff_members, patients, synthetic_records = build_dataset()
    write_csv_extracts(staff_members, patients, synthetic_records)
    print("Regenerated correlated CSV extracts via synthetic_data.py.")
