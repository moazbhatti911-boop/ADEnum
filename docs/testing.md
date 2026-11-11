# Testing

Test each PDF step before moving on.

## Unit tests (no live DC needed)

```bash
pytest -q
```

## Lab tests (on your own lab DC only)

1. Wrong password must fail with a clear message, not a crash.
2. User count must match Active Directory Users and Computers.
3. Domain Admins must appear in the privileged list.
4. Create a test account with password-never-expires and check it appears in the report.
5. With the DC switched off, you must get a clear error, not a crash.
