# Security policy

- Do **not** commit `config/accounts.yaml`, `.env`, or anything under `data/`.
- Do **not** add evidence exports, inventories, or scan outputs to this repository.
- Use `accounts.yaml.example` and `.env.example` as templates only.
- Before pushing, run a secret scan (e.g. `gitleaks detect --source .`).
