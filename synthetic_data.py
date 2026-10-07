"""
Unified synthetic data generator for the SecureEHR prototype.

This is the single source of truth for the data used across the system
(AESCTX.py and Evaluation.py). Everything it produces is referentially
consistent:

  * Staff belong to a department. Clinical staff (doctors, nurses) sit in one
    of the clinical departments; administrators sit in Administration.
  * Every patient is admitted under a clinical department and is assigned an
    attending doctor AND a primary nurse who both work in that same department.
  * Every clinical EHR record belongs to a real patient, inherits that
    patient's department, and is written by that patient's attending clinician.
    A patient's diagnosis, treatment and medication are drawn from a vocabulary
    specific to the department, so the clinical content matches the specialty.
  * Administrative records reference real staff accounts (account and key-
    management audit entries), which is the only data an administrator holds.

The generator is seeded, so the dataset is identical on every run (the
per-record ``patient_hash`` second factor is the deliberate exception: it is
drawn from ``secrets`` each run, because it models a live credential).

Run this file directly to (re)write the three CSV extracts:
    python synthetic_data.py
Import ``build_dataset()`` to get the in-memory dataset the app uses.
"""

import csv
import random
import secrets
from datetime import datetime, timedelta

from faker import Faker  # type: ignore

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SEED = 20261007

ROLES = ["doctor", "nurse", "admin"]
CLINICAL_DEPARTMENTS = ["Cardiology", "Oncology", "Pediatrics", "Emergency", "Neurology"]
ADMIN_DEPARTMENT = "Administration"
DEPARTMENTS = CLINICAL_DEPARTMENTS + [ADMIN_DEPARTMENT]

# Roster sizes per clinical department (anchors below are folded in on top).
DOCTORS_PER_DEPARTMENT = 5
NURSES_PER_DEPARTMENT = 7
NUM_ADMINS = 8

NUM_PATIENTS = 300
ENCOUNTERS_PER_PATIENT = (1, 2)   # inclusive range; each encounter -> 1 doctor + 1 nurse record
NUM_ADMIN_RECORDS = 110

# min_grade (clearance required) is weighted towards the lower, everyday values
# so most records are broadly accessible and only a few are highly restricted.
MIN_GRADE_CHOICES = [1, 2, 3, 4, 5]
MIN_GRADE_WEIGHTS = [38, 26, 18, 12, 6]
# A couple of departments handle more sensitive cases, nudging grades upwards.
SENSITIVE_DEPARTMENTS = {"Oncology", "Neurology"}

CSV_STAFF = "synthetic_user_records.csv"
CSV_PATIENTS = "synthetic_role_records.csv"
CSV_RECORDS = "synthetic_ehr_records.csv"

# -----------------------------------------------------------------------------
# Fixed "anchor" staff — kept stable so existing tests and scripts keep working.
# -----------------------------------------------------------------------------
ANCHOR_STAFF = [
    {"staff_id": "DOC001", "name": "Alice Bennett",   "role": "doctor", "department": "Cardiology", "grade": 4},
    {"staff_id": "DOC002", "name": "Evan Ramirez",    "role": "doctor", "department": "Neurology",  "grade": 3},
    {"staff_id": "NUR001", "name": "Bob Carter",      "role": "nurse",  "department": "Emergency",  "grade": 5},
    {"staff_id": "NUR002", "name": "Fiona Doyle",     "role": "nurse",  "department": "Pediatrics", "grade": 2},
    {"staff_id": "ADM001", "name": "Charlie Nkemuo",  "role": "admin",  "department": ADMIN_DEPARTMENT, "grade": 5},
    {"staff_id": "ADM002", "name": "Diana Osei",      "role": "admin",  "department": ADMIN_DEPARTMENT, "grade": 4},
]

# -----------------------------------------------------------------------------
# Department-specific clinical vocabulary (keeps content correlated to specialty)
# -----------------------------------------------------------------------------
CLINICAL = {
    "Cardiology": {
        "conditions": ["Atrial fibrillation", "Congestive heart failure", "Coronary artery disease",
                        "Essential hypertension", "Non-ST elevation myocardial infarction",
                        "Mitral valve regurgitation", "Stable angina", "Hyperlipidaemia"],
        "treatments": ["Started on beta-blocker therapy", "Scheduled for coronary angioplasty",
                       "Anticoagulation initiated and monitored", "24-hour Holter monitoring ordered",
                       "Referred for echocardiography", "Cardiac rehabilitation programme enrolled"],
        "medications": ["Atorvastatin 40mg", "Metoprolol 50mg", "Lisinopril 10mg",
                        "Apixaban 5mg", "Furosemide 20mg", "Clopidogrel 75mg"],
        "visits": ["Outpatient cardiology clinic", "Chest pain assessment", "Post-procedure review"],
    },
    "Oncology": {
        "conditions": ["Stage II breast carcinoma", "Non-Hodgkin lymphoma", "Colorectal adenocarcinoma",
                       "Prostate carcinoma", "Chemotherapy-induced neutropenia", "Metastatic melanoma",
                       "Chronic myeloid leukaemia"],
        "treatments": ["Commenced adjuvant chemotherapy cycle", "Referred for radiotherapy planning",
                       "Immunotherapy infusion administered", "Tumour board review completed",
                       "Supportive antiemetic therapy given", "Surveillance imaging scheduled"],
        "medications": ["Tamoxifen 20mg", "Ondansetron 8mg", "Capecitabine 500mg",
                        "Filgrastim injection", "Dexamethasone 4mg", "Pembrolizumab infusion"],
        "visits": ["Chemotherapy day unit", "Oncology follow-up", "Treatment planning review"],
    },
    "Pediatrics": {
        "conditions": ["Acute bronchiolitis", "Febrile seizure", "Paediatric asthma exacerbation",
                       "Acute otitis media", "Viral gastroenteritis", "Type 1 diabetes mellitus",
                       "Kawasaki disease"],
        "treatments": ["Nebulised bronchodilator administered", "Oral rehydration therapy started",
                       "Weight-based antibiotic course prescribed", "Admitted for overnight observation",
                       "Immunisation schedule updated", "Growth and development review"],
        "medications": ["Amoxicillin suspension", "Salbutamol inhaler", "Paracetamol 120mg/5ml",
                        "Prednisolone 5mg", "Oral rehydration salts", "Insulin aspart"],
        "visits": ["Paediatric emergency review", "General paediatrics clinic", "Well-child visit"],
    },
    "Emergency": {
        "conditions": ["Laceration requiring suturing", "Closed forearm fracture", "Acute appendicitis",
                       "Community-acquired pneumonia", "Anaphylactic reaction", "Mild head injury",
                       "Acute asthma attack", "Dehydration"],
        "treatments": ["Wound cleaned, closed and dressed", "Limb immobilised and splinted",
                       "Intravenous fluids and analgesia given", "Referred to surgical team",
                       "Nebuliser and steroids administered", "Observed and discharged with advice"],
        "medications": ["Paracetamol 1g IV", "Ceftriaxone 1g", "Adrenaline 0.5mg IM",
                        "Morphine 5mg", "Ondansetron 4mg", "Salbutamol nebules"],
        "visits": ["Emergency department attendance", "Resuscitation review", "Minor injuries unit"],
    },
    "Neurology": {
        "conditions": ["Acute ischaemic stroke", "Focal epilepsy", "Chronic migraine",
                       "Multiple sclerosis relapse", "Parkinson's disease", "Peripheral neuropathy",
                       "Transient ischaemic attack"],
        "treatments": ["Thrombolysis protocol initiated", "Antiepileptic therapy adjusted",
                       "MRI brain with contrast ordered", "Referred for nerve conduction studies",
                       "Disease-modifying therapy reviewed", "Physiotherapy and rehabilitation arranged"],
        "medications": ["Levetiracetam 500mg", "Sumatriptan 50mg", "Levodopa/carbidopa",
                        "Aspirin 300mg", "Gabapentin 300mg", "Interferon beta-1a"],
        "visits": ["Acute stroke unit", "Neurology outpatient clinic", "Seizure follow-up"],
    },
}

# -----------------------------------------------------------------------------
# Patient demographics vocabulary
# -----------------------------------------------------------------------------
SEXES = ["Female", "Male"]
BLOOD_TYPES = ["O+", "O-", "A+", "A-", "B+", "B-", "AB+", "AB-"]
BLOOD_WEIGHTS = [37, 7, 28, 6, 8, 2, 3, 1]
ALLERGIES = ["Penicillin", "Latex", "Peanuts", "Sulfa drugs", "Iodine contrast",
             "Aspirin", "Shellfish", "Pollen"]
CHRONIC_CONDITIONS = ["Type 2 diabetes", "Hypertension", "Asthma", "Chronic kidney disease",
                      "Hypothyroidism", "COPD", "Osteoarthritis", "Depression"]

ADMIN_ACTIONS = [
    ("Account provisioned", "Issued credentials and assigned role-based access."),
    ("Role key rotation", "Rotated the AES-256 key for the role on schedule."),
    ("Access review", "Audited record-access logs; no anomalies found."),
    ("Grade change approved", "Updated clearance grade after competency sign-off."),
    ("Account suspended", "Temporarily disabled access pending HR review."),
    ("Password reset", "Processed a verified password reset request."),
    ("Department transfer", "Moved the account to a new department roster."),
]


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _email(name, taken):
    """Build a unique hospital email from a person's name."""
    base = name.lower().replace("'", "").replace(".", "").replace(" ", ".")
    candidate = f"{base}@hospital.org"
    n = 2
    while candidate in taken:
        candidate = f"{base}{n}@hospital.org"
        n += 1
    taken.add(candidate)
    return candidate


def _min_grade(department):
    grade = random.choices(MIN_GRADE_CHOICES, weights=MIN_GRADE_WEIGHTS, k=1)[0]
    if department in SENSITIVE_DEPARTMENTS and grade < 5 and random.random() < 0.3:
        grade += 1
    return grade


def _list_field(pool, lo, hi):
    """Pick lo..hi distinct items from a pool and join them for a cell value."""
    k = random.randint(lo, hi)
    if k == 0:
        return "None recorded"
    return "; ".join(random.sample(pool, min(k, len(pool))))


# -----------------------------------------------------------------------------
# Generation
# -----------------------------------------------------------------------------
def _generate_staff(fake):
    """Return (staff_members dict, rosters) with every department covered."""
    staff_members = {}
    emails = set()
    rosters = {dept: {"doctor": [], "nurse": []} for dept in CLINICAL_DEPARTMENTS}

    doc_n = nur_n = adm_n = 0

    def add(staff_id, name, role, department, grade):
        username = staff_id.lower()
        staff_members[staff_id] = {
            "name": name,
            "email": _email(name, emails),
            "role": role,
            "department": department,
            "grade": grade,
            "username": username,
            "password": fake.password(length=12),
        }
        if role in ("doctor", "nurse") and department in rosters:
            rosters[department][role].append(staff_id)

    # Anchor staff first, so their IDs and details stay fixed.
    for s in ANCHOR_STAFF:
        add(s["staff_id"], s["name"], s["role"], s["department"], s["grade"])
        if s["staff_id"].startswith("DOC"):
            doc_n = max(doc_n, int(s["staff_id"][3:]))
        elif s["staff_id"].startswith("NUR"):
            nur_n = max(nur_n, int(s["staff_id"][3:]))
        elif s["staff_id"].startswith("ADM"):
            adm_n = max(adm_n, int(s["staff_id"][3:]))

    # Fill each clinical department to its target roster size.
    for dept in CLINICAL_DEPARTMENTS:
        while len(rosters[dept]["doctor"]) < DOCTORS_PER_DEPARTMENT:
            doc_n += 1
            add(f"DOC{doc_n:03d}", fake.name(), "doctor", dept, random.randint(1, 5))
        while len(rosters[dept]["nurse"]) < NURSES_PER_DEPARTMENT:
            nur_n += 1
            add(f"NUR{nur_n:03d}", fake.name(), "nurse", dept, random.randint(1, 5))

    # Administrators.
    while adm_n < NUM_ADMINS:
        adm_n += 1
        add(f"ADM{adm_n:03d}", fake.name(), "admin", ADMIN_DEPARTMENT, random.randint(3, 5))

    return staff_members, rosters


def _generate_patients(fake, staff_members, rosters):
    """Create patients, each tied to a department, attending doctor and nurse."""
    patients = []
    for i in range(1, NUM_PATIENTS + 1):
        department = random.choice(CLINICAL_DEPARTMENTS)
        attending = random.choice(rosters[department]["doctor"])
        primary_nurse = random.choice(rosters[department]["nurse"])
        sex = random.choice(SEXES)
        admission = datetime.now() - timedelta(days=random.randint(0, 900),
                                               minutes=random.randint(0, 1440))
        patients.append({
            "patient_id": f"PAT{i:04d}",
            "mrn": f"MRN-{random.randint(10_000_000, 99_999_999)}",
            "name": fake.name_female() if sex == "Female" else fake.name_male(),
            "age": random.randint(1, 95) if department == "Pediatrics" else random.randint(16, 95),
            "sex": sex,
            "blood_type": random.choices(BLOOD_TYPES, weights=BLOOD_WEIGHTS, k=1)[0],
            "department": department,
            "attending_doctor": attending,
            "attending_doctor_name": staff_members[attending]["name"],
            "primary_nurse": primary_nurse,
            "primary_nurse_name": staff_members[primary_nurse]["name"],
            "allergies": _list_field(ALLERGIES, 0, 2),
            "chronic_conditions": _list_field(CHRONIC_CONDITIONS, 0, 2),
            "admission_date": admission,
        })
    # Pediatrics patients should skew young.
    for p in patients:
        if p["department"] == "Pediatrics":
            p["age"] = random.randint(0, 16)
    return patients


def _clinical_record(ehr_id, role, patient, encounter):
    """Build one clinical EHR record (doctor or nurse) for a patient encounter."""
    if role == "doctor":
        attending_id = patient["attending_doctor"]
        attending_name = patient["attending_doctor_name"]
    else:
        attending_id = patient["primary_nurse"]
        attending_name = patient["primary_nurse_name"]
    return {
        "ehr_id": ehr_id,
        "assigned_role": role,
        "patient_id": patient["patient_id"],
        "mrn": patient["mrn"],
        "patient_name": patient["name"],
        "age": patient["age"],
        "sex": patient["sex"],
        "blood_type": patient["blood_type"],
        "allergies": patient["allergies"],
        "chronic_conditions": patient["chronic_conditions"],
        "department": patient["department"],
        "attending_id": attending_id,
        "attending_name": attending_name,
        "visit_type": encounter["visit_type"],
        "diagnosis": encounter["diagnosis"],
        "treatment": encounter["treatment"],
        "medications": encounter["medications"],
        "timestamp": encounter["timestamp"].isoformat(timespec="seconds"),
        "key_id": f"{role.upper()}_AES256",
        "patient_hash": secrets.token_hex(16),
        "min_grade": encounter["min_grade"],
    }


def _admin_record(ehr_id, subject, performed_by):
    """Build one administrative audit record referencing a real staff account."""
    action, detail = random.choice(ADMIN_ACTIONS)
    ts = datetime.now() - timedelta(days=random.randint(0, 600), minutes=random.randint(0, 1440))
    return {
        "ehr_id": ehr_id,
        "assigned_role": "admin",
        "patient_id": subject["staff_id"],          # the account this entry concerns
        "subject_name": subject["name"],
        "subject_role": subject["role"],
        "department": ADMIN_DEPARTMENT,
        "attending_id": performed_by,
        "attending_name": None,
        "visit_type": "Administrative action",
        "diagnosis": action,                         # reused fields keep one record schema
        "treatment": detail,
        "medications": "N/A",
        "timestamp": ts.isoformat(timespec="seconds"),
        "key_id": "ADMIN_AES256",
        "patient_hash": secrets.token_hex(16),
        "min_grade": random.randint(3, 5),
    }


def build_dataset():
    """Build the full correlated dataset.

    Returns (staff_members, patients, synthetic_records) where synthetic_records
    is a dict keyed by role, each a list of record dicts with ``ehr_id`` unique
    within that role. Doctor and nurse records share ehr_id numbering because
    each patient encounter produces exactly one of each.
    """
    random.seed(SEED)
    Faker.seed(SEED)
    fake = Faker()
    fake.unique.clear()

    staff_members, rosters = _generate_staff(fake)
    patients = _generate_patients(fake, staff_members, rosters)

    doctor_records, nurse_records = [], []
    ehr = 0
    for patient in patients:
        for _ in range(random.randint(*ENCOUNTERS_PER_PATIENT)):
            ehr += 1
            vocab = CLINICAL[patient["department"]]
            encounter = {
                "visit_type": random.choice(vocab["visits"]),
                "diagnosis": random.choice(vocab["conditions"]),
                "treatment": random.choice(vocab["treatments"]),
                "medications": _pick_medications(vocab["medications"]),
                "timestamp": patient["admission_date"] + timedelta(minutes=random.randint(0, 2880)),
                "min_grade": _min_grade(patient["department"]),
            }
            doctor_records.append(_clinical_record(ehr, "doctor", patient, encounter))
            nurse_records.append(_clinical_record(ehr, "nurse", patient, encounter))

    admin_subjects = list(staff_members.items())
    admins = [sid for sid, s in admin_subjects if s["role"] == "admin"]
    admin_records = []
    for i in range(1, NUM_ADMIN_RECORDS + 1):
        sid, s = random.choice(admin_subjects)
        subject = dict(s, staff_id=sid)
        admin_records.append(_admin_record(i, subject, random.choice(admins)))

    synthetic_records = {
        "doctor": doctor_records,
        "nurse": nurse_records,
        "admin": admin_records,
    }
    return staff_members, patients, synthetic_records


def _pick_medications(pool):
    k = random.randint(1, 3)
    return "; ".join(random.sample(pool, min(k, len(pool))))


# -----------------------------------------------------------------------------
# Backward-compatible helper used by Evaluation.py for scalability benchmarks.
# -----------------------------------------------------------------------------
def generate_synthetic_ehr_records_by_role(role, num_records=100):
    """Standalone record generator kept for timing/scalability benchmarks.

    Produces ``num_records`` self-contained records for the given role, matching
    the correlated schema's shape (department-appropriate clinical content).
    Not tied to the patient master — it exists only to feed encryption timings.
    """
    records = []
    departments = CLINICAL_DEPARTMENTS if role in ("doctor", "nurse") else [ADMIN_DEPARTMENT]
    for i in range(1, num_records + 1):
        department = random.choice(departments)
        if role == "admin":
            diagnosis, treatment = random.choice(ADMIN_ACTIONS)
            medications = "N/A"
            visit = "Administrative action"
        else:
            vocab = CLINICAL[department]
            diagnosis = random.choice(vocab["conditions"])
            treatment = random.choice(vocab["treatments"])
            medications = _pick_medications(vocab["medications"])
            visit = random.choice(vocab["visits"])
        records.append({
            "ehr_id": i,
            "patient_id": f"{role.upper()}_PAT_{i:04d}",
            "assigned_role": role,
            "department": department,
            "visit_type": visit,
            "diagnosis": diagnosis,
            "treatment": treatment,
            "medications": medications,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "key_id": f"{role.upper()}_AES256",
            "patient_hash": secrets.token_hex(16),
            "min_grade": random.randint(1, 5),
        })
    return records


# -----------------------------------------------------------------------------
# CSV extracts
# -----------------------------------------------------------------------------
def _write_csv(filename, fieldnames, rows):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"  {filename}: {len(rows)} rows")


def write_csv_extracts(staff_members, patients, synthetic_records):
    print("Writing CSV extracts:")

    staff_rows = [dict(s, staff_id=sid) for sid, s in staff_members.items()]
    _write_csv(CSV_STAFF,
               ["staff_id", "username", "password", "name", "email", "role", "department", "grade"],
               staff_rows)

    patient_rows = [dict(p, admission_date=p["admission_date"].strftime("%Y-%m-%d %H:%M"))
                    for p in patients]
    _write_csv(CSV_PATIENTS,
               ["patient_id", "mrn", "name", "age", "sex", "blood_type", "department",
                "attending_doctor", "attending_doctor_name", "primary_nurse",
                "primary_nurse_name", "allergies", "chronic_conditions", "admission_date"],
               patient_rows)

    # Clinical records only in the EHR extract (patient_hash is a secret, excluded).
    clinical = synthetic_records["doctor"] + synthetic_records["nurse"]
    record_rows = []
    for r in clinical:
        row = dict(r)
        row["ehr_id"] = f"{r['assigned_role'][:3].upper()}-{r['ehr_id']:04d}"
        record_rows.append(row)
    _write_csv(CSV_RECORDS,
               ["ehr_id", "assigned_role", "patient_id", "mrn", "patient_name", "age", "sex",
                "blood_type", "department", "attending_id", "attending_name", "visit_type",
                "diagnosis", "treatment", "medications", "min_grade", "key_id", "timestamp"],
               record_rows)


if __name__ == "__main__":
    staff_members, patients, synthetic_records = build_dataset()
    print(f"Generated {len(staff_members)} staff, {len(patients)} patients, "
          f"{sum(len(v) for v in synthetic_records.values())} records "
          f"(doctor={len(synthetic_records['doctor'])}, "
          f"nurse={len(synthetic_records['nurse'])}, "
          f"admin={len(synthetic_records['admin'])}).")
    write_csv_extracts(staff_members, patients, synthetic_records)
    print("Done.")
