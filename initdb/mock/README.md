# XSIAM Mock Data

Generate and import high-volume mock data for every XSIAM business collection.

Default volume is at least 1,000,000 total documents across all collections, with
every collection populated. Alerts, incidents, assets, IOCs, vulnerabilities,
exposure scores, audit logs, and causality graph data receive most of the rows.

## Generate Only

```powershell
python .\initdb\mock\generate_mock_data.py --out .\initdb\mock\data --total 1000000
```

## Generate And Import

```powershell
.\initdb\mock\import_mock_data.ps1 -Generate
```

The import script:

- runs the base `initdb\run_init_xsiamdb.ps1` schema initializer first
- drops and recreates `xsiamdb` through the base initializer
- truncates all business collections after schema creation so base seed data is
  not mixed into mock datasets
- imports each `*.jsonl` file with `arangoimport --on-duplicate update`
- validates that at least 1,000,000 documents exist after import

Mock login data:

- Admin: `admin` / `admin`
- Other generated users: `user0000001@example.local` ... with password
  `User@123456`
- Passwords are stored as bcrypt `password_hash` values.

## Validate Counts

```powershell
.\initdb\mock\validate_mock_counts.ps1
```

## Output

Generated files are written to:

```text
initdb/mock/data/
```

The `data/` directory is generated output and can be deleted/recreated at any
time.
