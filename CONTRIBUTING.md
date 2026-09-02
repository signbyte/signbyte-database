# Contributing

Thank you for your interest. This repository is **generated**: its whole content is
derived from an upstream source tree and replaced wholesale on every publish. That
shapes how contributions work:

- **Issues are welcome** — a bug in a procedure, a missing index, a hardening gap, a
  documentation error. Describe what you observed, against which commit or image
  tag, and how to reproduce it.
- **Pull requests are not accepted here.** A change merged into this repository
  would be overwritten by the next publish. Please open an issue instead; fixes are
  made at the source and arrive here with the next publish, with your report
  credited.
- For anything that could be exploited, use the private route in
  [SECURITY.md](SECURITY.md) — never a public issue.

## Running the checks yourself

You need Docker only. The gate every publish passes:

```sh
testing/verify.sh      # build the image, migrate the schema set twice, assert, fail-closed proofs
testing/sql-tests.sh   # SQL unit tests, role-leak acceptance, plpgsql_check static analysis
```

## Licence

This project is licensed under the GNU AGPL-3.0-only (see [LICENSE](LICENSE)). Reports
and suggestions you send us may be incorporated under the same licence.
