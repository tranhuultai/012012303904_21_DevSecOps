# DevSecOps Security Summary (g2)

> Generated automatically on 2026-11-14 21:37 UTC.

## Gate result

**Decision: WARN**

Warnings were detected. The current policy allows the pipeline to continue, but the findings should be reviewed.

## Overview

| Metric | Count |
|---|---:|
| Total findings | 265 |
| Blockers | 0 |
| Warnings | 20 |
| Warnings linked to source findings | 20 |
| Active exceptions used | 0 |
| Expired exceptions | 0 |

## Findings by severity

| Severity | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 111 |
| MEDIUM | 69 |
| LOW | 20 |
| INFO | 65 |

## Findings by tool

| Tool | Count |
|---|---:|
| semgrep | 0 |
| gitleaks | 0 |
| trivy | 11 |
| checkov | 50 |
| grype | 204 |

## Blocking findings

No blocking findings reported by the security gate.

## Warning findings

| Severity | Tool | Finding | Package / resource | Location | Policy / source IDs |
|---|---|---|---|---|---|
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2025-69720 | libncursesw6 6.5+20250216-2<br>libtinfo6 6.5+20250216-2<br>ncurses-base 6.5+20250216-2<br>ncurses-bin 6.5+20250216-2 | `/var/lib/dpkg/info/libncursesw6:amd64.md5sums; /usr/share/doc/libtinfo6/copyright; /usr/share/doc/ncurses-base/copyright; /usr/share/doc/ncurses-bin/copyright` | `warn:0`<br>`grype:cf9cdd4682b46020`<br>`grype:cbd0d4a72eff5789`<br>`grype:40b283860e25b791`<br>`grype:2d77c0490654841a` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-102010 | gcc-14-base 14.2.0-19<br>libgcc-s1 14.2.0-19<br>libstdc++6 14.2.0-19 | `/usr/share/doc/gcc-14-base/copyright` | `warn:1`<br>`grype:412202f563c4ccbf`<br>`grype:efc77dc9f1e5c106`<br>`grype:9ad53ce58c03758a` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-119373 | libsqlite3-0 3.46.1-7+deb13u2 | `/usr/share/doc/libsqlite3-0/copyright` | `warn:2`<br>`grype:82ca9e8db8d77593` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-119374 | libsqlite3-0 3.46.1-7+deb13u2 | `/usr/share/doc/libsqlite3-0/copyright` | `warn:3`<br>`grype:aac0b2962cd57d16` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-119379 | libsqlite3-0 3.46.1-7+deb13u2 | `/usr/share/doc/libsqlite3-0/copyright` | `warn:4`<br>`grype:d08e8650da441f7c` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-19499 | libc-bin 2.41-12+deb13u4<br>libc6 2.41-12+deb13u4 | `/usr/share/doc/libc-bin/copyright; /usr/share/doc/libc6/copyright` | `warn:5`<br>`grype:41b9ca3e32680969`<br>`grype:f6e666f94c777744` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-5435 | libc-bin 2.41-12+deb13u4<br>libc6 2.41-12+deb13u4 | `/usr/share/doc/libc-bin/copyright; /usr/share/doc/libc6/copyright` | `warn:6`<br>`grype:320bdfe1ae87a96b`<br>`grype:ce484e665cf5d2ae` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-54369 | libacl1 2.3.2-2+b1 | `/usr/share/doc/libacl1/copyright` | `warn:7`<br>`grype:dbc0281c9e49aca1` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-54370 | libacl1 2.3.2-2+b1 | `/usr/share/doc/libacl1/copyright` | `warn:8`<br>`grype:cef09ecc4358952e` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-76642 | bsdutils 1:2.41.5-0+deb13u1<br>libblkid1 2.41.5-0+deb13u1<br>liblastlog2-2 2.41.5-0+deb13u1<br>libmount1 2.41.5-0+deb13u1<br>libsmartcols1 2.41.5-0+deb13u1<br>+4 more | `/usr/share/doc/bsdutils/copyright; /usr/share/doc/libblkid1/copyright; /usr/share/doc/liblastlog2-2/copyright; /usr/share/doc/libmount1/copyright; /usr/share/doc/libsmartcols1/copyright; /usr/share/doc/libuuid1/copyright; /usr/share/doc/login/copyright; /usr/share/doc/mount/copyright; /usr/share/doc/util-linux/copyright` | `warn:9`<br>`grype:2b71d2b21a935500`<br>`grype:a6279fffd3357091`<br>`grype:b27e4b9aa46c13e8`<br>`grype:dd5367654a945f5d`<br>`grype:8bf590853cc3fa0c`<br>`+4 more source findings` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-78408 | bsdutils 1:2.41.5-0+deb13u1<br>libblkid1 2.41.5-0+deb13u1<br>liblastlog2-2 2.41.5-0+deb13u1<br>libmount1 2.41.5-0+deb13u1<br>libsmartcols1 2.41.5-0+deb13u1<br>+4 more | `/usr/share/doc/bsdutils/copyright; /usr/share/doc/libblkid1/copyright; /usr/share/doc/liblastlog2-2/copyright; /usr/share/doc/libmount1/copyright; /usr/share/doc/libsmartcols1/copyright; /usr/share/doc/libuuid1/copyright; /usr/share/doc/login/copyright; /usr/share/doc/mount/copyright; /usr/share/doc/util-linux/copyright` | `warn:10`<br>`grype:b01383d47e1f15b4`<br>`grype:15357ed51543f9f7`<br>`grype:7ef9ed8bfe314f23`<br>`grype:9ea927f9de19fefc`<br>`grype:a5442957cd04c015`<br>`+4 more source findings` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-78409 | bsdutils 1:2.41.5-0+deb13u1<br>libblkid1 2.41.5-0+deb13u1<br>liblastlog2-2 2.41.5-0+deb13u1<br>libmount1 2.41.5-0+deb13u1<br>libsmartcols1 2.41.5-0+deb13u1<br>+4 more | `/usr/share/doc/bsdutils/copyright; /usr/share/doc/libblkid1/copyright; /usr/share/doc/liblastlog2-2/copyright; /usr/share/doc/libmount1/copyright; /usr/share/doc/libsmartcols1/copyright; /usr/share/doc/libuuid1/copyright; /usr/share/doc/login/copyright; /usr/share/doc/mount/copyright; /usr/share/doc/util-linux/copyright` | `warn:11`<br>`grype:d75371fd5690abe4`<br>`grype:41e7a9abb17c6697`<br>`grype:780e932e4c494505`<br>`grype:eb4cfc31e9c8469a`<br>`grype:aa2ccc651b33af5c`<br>`+4 more source findings` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-78410 | bsdutils 1:2.41.5-0+deb13u1<br>libblkid1 2.41.5-0+deb13u1<br>liblastlog2-2 2.41.5-0+deb13u1<br>libmount1 2.41.5-0+deb13u1<br>libsmartcols1 2.41.5-0+deb13u1<br>+4 more | `/usr/share/doc/bsdutils/copyright; /usr/share/doc/libblkid1/copyright; /usr/share/doc/liblastlog2-2/copyright; /usr/share/doc/libmount1/copyright; /usr/share/doc/libsmartcols1/copyright; /usr/share/doc/libuuid1/copyright; /usr/share/doc/login/copyright; /usr/share/doc/mount/copyright; /usr/share/doc/util-linux/copyright` | `warn:12`<br>`grype:c3525cc58ddc18e1`<br>`grype:838cd2d18858a41a`<br>`grype:9e15a8e4691a69a6`<br>`grype:7ff5cfb2becaf226`<br>`grype:12c18efc77e4468e`<br>`+4 more source findings` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-82560 | perl-base 5.40.1-6+deb13u1 | `/var/lib/dpkg/info/perl-base.list` | `warn:13`<br>`grype:c79f27e61d788be8` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-84243 | libc-bin 2.41-12+deb13u4<br>libc6 2.41-12+deb13u4 | `/usr/share/doc/libc-bin/copyright; /usr/share/doc/libc6/copyright` | `warn:14`<br>`grype:8bc01529f253995f`<br>`grype:5b88a906fe752d65` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-9538 | perl-base 5.40.1-6+deb13u1 | `/var/lib/dpkg/info/perl-base.list` | `warn:15`<br>`grype:26ef4c0d5c9de92a` |
| HIGH | grype | WARN HIGH chưa có bản vá: CVE-2026-95619 | gcc-14-base 14.2.0-19<br>libgcc-s1 14.2.0-19<br>libstdc++6 14.2.0-19 | `/usr/share/doc/gcc-14-base/copyright` | `warn:16`<br>`grype:7416cd9f1b60e7d4`<br>`grype:d81a0a7e98156d96`<br>`grype:e040253894299fea` |
| HIGH | checkov, trivy | WARN IaC controls require review: AWS-0077, AWS-0090, AWS-0132, AWS-0176, AWS-0177, AWS-0178, CKV2_AWS_11, CKV2_AWS_12, CKV2_AWS_30, CKV_AWS_129, CKV_AWS_145, CKV_AWS_161, CKV_AWS_21, CKV_AWS_226, CKV_AWS_293, CKV_K8S_35, KSV-0125 | aws_db_instance.main<br>aws_vpc.main<br>aws_s3_bucket.logs<br>aws_s3_bucket.app<br>Deployment.default.devsecops-app<br>+7 more | `/rds.tf:26; /network.tf:5; /s3.tf:1; /s3.tf:13; /deploy/deployment.yaml:1; deploy/deployment.yaml; infra/network.tf; infra/rds.tf; infra/s3.tf` | `warn:17`<br>`checkov:e5c249b1b6057966`<br>`checkov:ca6faac2c7f180f0`<br>`checkov:b4fc745afb07e82c`<br>`checkov:20a48d2d9745f902`<br>`checkov:58bf1a93f936c822`<br>`+13 more source findings` |
| MEDIUM | grype | WARN MEDIUM có bản vá: CVE-2025-15367 | python 3.13.18 → 3.15.0a6 | `/usr/local/bin/python3.13` | `warn:18`<br>`grype:0687124b692f72e2` |
| MEDIUM | grype | WARN MEDIUM có bản vá: CVE-2026-116566 | python 3.13.18 → 3.16.0 | `/usr/local/bin/python3.13` | `warn:19`<br>`grype:630701e199bea7a9` |

## Exception review

- Expired exceptions: **0**
- Unused exceptions: **0**

---

_This report is generated from normalized scanner findings and the security gate report. It does not replace manual security review._
