# Third-party notices

This repository is distributed under the [Elastic License 2.0](./LICENSE) (see the `License` section of the root [`README.md`](./README.md)). This file lists content incorporated from other projects under their own, different licenses, as required by those licenses.

## `cloudflare/security-audit-skill` (MIT License)

Some checklist items in `security-review/checklists/core/` are adapted — reworded to fit this project's checklist format (see `security-review/checklists/_meta.md`), not copied verbatim — from Cloudflare's [`security-audit-skill`](https://github.com/cloudflare/security-audit-skill), specifically its `ATTACK-CLASSES.md` ("Business logic", "Feature abuse and data leakage", "Chained vulnerabilities and trust boundaries", "Obvious things" sections) and `DATA-ISOLATION-AND-LIFECYCLE.md` documents.

Affected files:

- `security-review/checklists/core/business-logic.md` (new file — state-machine violations and non-monetary check-then-act races)
- `security-review/checklists/core/disclosure.md` (export/backup as exfiltration, search/filter/sort as oracle, preview/draft/staging leakage, repository and git-history hygiene)
- `security-review/checklists/core/data-access.md` (import/restore as injection and validation bypass)
- `security-review/checklists/core/injection.md` (second-order injection — data safe in one context, dangerous when reused in another)
- `security-review/checklists/core/ssrf-fileops.md` (notification/webhook URL as SSRF — extension of existing content)

The MIT License requires that the copyright notice and permission notice below be preserved in copies and substantial portions of the licensed software. Reproduced verbatim from the upstream `LICENSE` file:

```
MIT License

Copyright (c) 2025-2026 Cloudflare, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

This MIT notice covers only the content listed above. It does not relicense any other part of this repository, which remains under the Elastic License 2.0.
