# Maintainers

See the information about community membership roles to learn about the role of the maintainers and the process to become one.

## Organization-Level Maintainers

| Name          | Email                        | GitHub                                     |
|---------------|------------------------------|--------------------------------------------|
| Dan Ghita     | dghita@wallix.com            | [@DanGhita](https://github.com/DanGhita)   |
| Jan Martens   | jan@martens.eu.org           | [@JanMa](https://github.com/JanMa)         |
| Nathan Phelps | naphelps@us.ibm.com          | [@naphelps](https://github.com/naphelps)   |
| Alex Scheel   | alexander.m.scheel@gmail.com | [@cipherboy](https://github.com/cipherboy) |

## Repository-Level Committers

| Name             | GitHub                                  | Projects                                                                                          |
| ---------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Andrii Fedorchuk | [@driif](https://github.com/driif) | [`vault/`](https://github.com/openbao/openbao/tree/main/vault) |
| Christoph Voigt  | [@voigt](https://github.com/voigt) | [`vault/`](https://github.com/openbao/openbao/tree/main/vault) |
| Dave Dykstra     | [@DrDaveD](https://github.com/DrDaveD) | [`auth/jwt` and `auth/oidc`](https://github.com/openbao/openbao/tree/main/builtin/credential/jwt) |
| Jonas Köhnen     | [@satoqz](https://github.com/satoqz) | [`vault/`](https://github.com/openbao/openbao/tree/main/vault) |
| Pascal Reeb      | [@pree](https://github.com/pree) | [helm](https://github.com/openbao/openbao-helm), [csi-provider](https://github.com/openbao/openbao-csi-provider), [k8s](https://github.com/openbao/openbao-k8s), and [secrets-operator](https://github.com/openbao/openbao-secrets-operator) |
| Tom Gehrke       | [@phyrog](https://github.com/phyrog) | [`vault/`](https://github.com/openbao/openbao/tree/main/vault) |
| Toni Tauro       | [@eyenx](https://github.com/eyenx) | [helm](https://github.com/openbao/openbao-helm), [csi-provider](https://github.com/openbao/openbao-csi-provider), [k8s](https://github.com/openbao/openbao-k8s), and [secrets-operator](https://github.com/openbao/openbao-secrets-operator) |
| Wojciech Slabosz | [@wslabosz-reply](https://github.com/wslabosz-reply) | [`vault/`](https://github.com/openbao/openbao/tree/main/vault) |
| Yannis           | [@Nerkho](https://github.com/Nerkho) | [helm](https://github.com/openbao/openbao-helm), [csi-provider](https://github.com/openbao/openbao-csi-provider), [k8s](https://github.com/openbao/openbao-k8s), and [secrets-operator](https://github.com/openbao/openbao-secrets-operator) |
| Geoffrey Wilson  | [@suprjinx](https://github.com/suprjinx) | [`vault/`](https://github.com/openbao/openbao/tree/main/vault) |

## Organization-Level Moderators

| Name            | GitHub                                                   |
| --------------- | -------------------------------------------------------- |
| Fatima Patel    | [@fatima2003](https://github.com/fatima2003)             |
| Gabriel Santos  | [@Gabrielopesantos](https://github.com/Gabrielopesantos) |
| Michael Hofer   | [@karras](https://github.com/karras)                     |

# OpenBao Community Roles

## Background

OpenBao is an open source secrets management application and is a critical
point of infrastructure for many organizations. It is important to be mindful
of supply chain security and the threat of intentionally or accidentally
malicious maintainers in order to build the trust of relying organizations.
However, OpenBao uses a plugin architecture and benefits from broad
integration with many specialized components (cloud providers, databases, key
management systems, platform services such as Kubernetes, ...). It is also
important to nurture this wide ecosystem and grant permissions to community
members familiar with these areas. OpenBao's community structure should
reflect this.

## Overview

OpenBao adheres to a three-tiered community role structure:

 1. The TSC-appointed organization-level maintainers, and
 2. Repository-level committers.
 3. Organization-level moderators.

The [core OpenBao repository](https://github.com/openbao/openbao) is excluded
from repository-level committers.

The `CODEOWNERS` and `MAINTAINERS.md` file of each repository will reflect the
maintenance requirements of both the organization and the repository.

### Organization-Level Maintainers

Organization-level maintainers will have admin purview over all projects under
the OpenBao GitHub organization. They will be ultimately responsible for
administration of repository, including configuration of the repository,
managing GitHub secrets, and ensuring compliance with Linux Foundation and
project requirements.

#### Eligibility

The following groups of people are eligible to become maintainers:

1. Current employees of active TSC member companies,
2. Former employees of active or former TSC member companies, or HashiCorp,
   who contributed during their tenure at the company and continue contributing,
3. Active repository-level committers who have been in their role for 1 year or
   repository committers who have actively maintain 5+ repositories for the last
   6 months, and
4. Past organization-level maintainers.

Significant contributions to OpenBao are required, for example:

1. Contributing impactful RFCs to the project,
2. Leading review and ownership of particular areas of code (such as core
   cryptography components or documentation), or
3. Large feature development or important bug fixes.

Eligibility requirements may be waived by 2/3rds majority TSC vote.

#### Applications

Applications to become organization-level maintainers will be sent to the
[OpenBao mailing list](https://lists.openssf.org/g/openbao) and should contain
motivation and confirmation of eligibility.

#### Elections

Organization-level maintainers are to be approved by unanimous vote of the
TSC and existing organization-level maintainers, allowing abstentions, at
2/3rds quorum.

#### Recall

Organization-level maintainers will forfeit with 2/3rd majority vote their
access after 30 days of inactivity without prior notice to any member of the
TSC or other organization-level maintainers. If a maintainer comes back and
demonstrates renewed contributions, a simple majority vote of any body should
be sufficient to reinstate them.

### Repository-Level Committers

Repository-level maintainers will have limited scope over specific projects
under the OpenBao GitHub organization. They will receive `write` permissions
to specific repositories, excluding the [core OpenBao repository](https://github.com/openbao/openbao).

#### Eligibility

The following groups of people are eligible to be committers:

1. Active moderators who have held the position for 90 days, and
2. Former committers and organization-level maintainers, and
3. Past HashiCorp employees who contributed during their tenure at the company.

Repository committers should demonstrate expertise in the requested project
and show a committment to making meaningful changes and maintaining security.

Eligibility requirements may be waived by simple majority TSC vote.

#### Applications

Applications to become committers will be sent to the
[OpenBao mailing list](https://lists.openssf.org/g/openbao) and should contain
brief motivation, confirmation of eligibility, and the repository/repositories
to receive committer access.

#### Elections

Per OpenBao Charter, repository-level committers are to be approved by 2/3rd
vote of the organization-level maintainers and project-level committers.

#### Recall

Repository-level committers will forfeit with 2/3rd majority vote their access
after 30 days of inactivity without prior notice to any member of the TSC or
other maintainers (organization-level or repository-level). If a committer
comes back and demonstrates renewed contributions, a simple majority vote of
either the TSC or the organization-level maintainers should be sufficient to
reinstate them.

### Organization-Level Moderators

Moderators will have power to apply labels to and open and close issues and
PRs and to manage discussions. They'll have moderation permissions on comments
to hide off-topic comments or edit comments for formatting.

#### Eligibility

All contributors who have been active in the project for 60 days are eligible
to become moderators.

Eligibility requirements may be waived by simple majority TSC or
organization-level maintainers vote.

#### Applications

Applications to become moderators will be sent to the [OpenBao mailing list](https://lists.openssf.org/g/openbao).

#### Elections

Moderators will be subject to approval by simple majority vote of
organization-level maintainers and project-level committers, subject to
2/3rds quorum.

#### Recall

Moderators who have been inactive for 60 days will have their access revoked.
