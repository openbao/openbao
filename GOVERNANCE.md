# TSC Membership Criteria and Processes

## Background

OpenBao's TSC was formed [in June 2024](https://wiki.lfedge.org/display/OH/2024-06-13+OpenBao+TSC+Meeting), initiating the startup period defined [in the charter, clause 2.b](https://openbao.org/assets/OpenBao-Technical-Charter-Final-2024-05-08.pdf). During the startup period, one of the requirements is to define a process for TSC membership, per charter clause 2.c. This document aims to define TSC membership roles and processes for the selection of members.

In May 2025, OpenBao moved from LF Edge [to the OpenSSF](https://github.com/ossf/tac/pull/461), becoming a sandbox project there.

This document outlines the mechanism by which the TSC grows and shrinks its governing member body. TSC membership is meant to provide significant recognition in the community and thus has a substantial barrier to entry.

## Membership Types

There are two types of membership on OpenBao's TSC:

1. Individual membership, tied to a particular individual regardless of employer.
2. Corporate membership, tied to a particular company or organization and continuing independent of choice of representative.

Individual memberships are eligible for only a single position with no backup.

Corporate memberships may designate a primary representative and a single backup representative, both with voting permissions on behalf of the organization (counting towards a single vote). Either official representative may designate, in writing to the [TSC mailing list](https://lists.openssf.org/g/openbao-tsc), a fallback individual with voting permissions specifically for a particular meeting(s). Other employees of the company, not expressly authorized, will not have voting permissions.

Individuals may not be both a corporate representative and an individual member. An individual may either be a designated corporate representative or an individual member at a given time; they resign their existing position upon successful acceptance as a member in another role (either by voting of the TSC to become an individual member if their employer no longer wishes to be a member but they wish to continue in a personal capacity; or by appointment as a primary or backup member of a TSC corporate member if their employment changes or their company becomes a TSC member directly). Only one vote on the TSC is allowed per corporate entity, in the broadest sense including subsidiaries, parent company, and employer/employee relationships, is permitted.

## Membership Eligibility

1. Any prior or existing OpenBao TSC corporate member, seeking a corporate membership; or
2. Any prior or existing OpenBao TSC individual member, seeking either an individual or corporate membership; or
3. Any prior primary or backup OpenBao TSC representative from a corporate member, seeking either an individual or corporate membership; or
4. Any chair of an OpenBao Working Group, seeking either an individual or corporate membership; or
5. Any _substantial_ individual or corporate _contributor_ to OpenBao ("the community").

Membership in either the Linux Foundation or the OpenSSF subproject is not a requirement.

A _substantial contributor_ (whether individual or corporate) is defined as someone meeting multiple of the following:

1. Anyone who makes material, repeated direct contributions to the documentation or code of OpenBao or other first-party projects, such as OpenBao's website, OpenBao's core binary, OpenBao's plugins, or OpenBao's Kubernetes enablement; or
2. Anyone who makes material, repeated design contributions, such as RFCs, design documents, UX research; or
3. Anyone who makes material, repeated product contributions, such as building roadmaps, identifying and meeting with relevant stakeholders, or monitoring or tracking contributions and progress towards goals; or
4. Anyone who makes material, repeated community stewardship contributions, such as triaging issues, publishing blog posts or other information articles about the community, or attending, advocating at, or sponsoring conferences and mentioning OpenBao, or otherwise helping to grow the size and impact of the community; or
5. Anyone who makes material, repeated project leadership contributions, such as participating in Working Group or TSC processes; or
6. Anyone who helps validate and use the community's collective work, such as performing releases, validating release artifacts, or helping run OpenBao in production; or
7. Anyone who has provided substantial monetary contributions to the community, either directly to the OpenBao TSC under the OpenSSF or via full- or part-time employment of individuals contributing to OpenBao; or
8. Anyone who has satisfying the above criteria applied to HashiCorp Vault and have demonstrated a repeated commitment to contributing to this fork going forward. This does not preclude further contributions to HashiCorp Vault if the member so feels inclined.
9. Anyone who makes substantial monetary contributions relative to organization and project size, such as sponsoring full-time maintainers, mentorships, travel, or via direct donation to the project.

These criteria are to be evaluated by the TSC based on the membership application. They are meant to be somewhat subjective but obvious when met: a good application will likely have deep contributions in one or more areas and light contributions in many others. Not all of an applicant company's contributors need to meet these goals: the collective contributions of all, with at least one individual with substantial contributions or multiple criteria, would be sufficient.

## Membership Application

Any eligible member may submit an application to the [TSC mailing list](https://lists.openssf.org/g/openbao-tsc). This email should document evidence of meeting one or more of the above eligibility criteria.

At the next TSC meeting and immediately via email, the TSC will consider the validity of the request and ask any necessary clarifying questions of the individual or corporation. It is encouraged the individual or corporation be present at the meeting, though in lieu, may answer questions via email.

## Membership Voting

Per charter clause 8.a, adding a TSC member can be done by 2/3rds majority vote of the existing OpenBao TSC, subject to to the quorum requirement in charter clause 3.b. This may happen at a TSC meeting or via separate voting conducted by OpenSSF at the TSC's discretion. This vote is subject to approval by OpenSSF per said charter clause. A membership inclusion vote may also be held electronically.

Membership is effective immediately after the conclusion of the TSC meeting in which membership was granted. The TSC Chair shall be responsible for updating the [CONTRIBUTING.md](https://github.com/openbao/openbao/blob/main/CONTRIBUTING.md#technical-steering-committee-tsc-members) file and any other relevant pages.

### TSC Chair Elections

As designated in charter clause 2.g and per voting criteria in charter clause 3.c, the TSC members may vote to elect a TSC chair by simple majority vote, subject to the quorum requirement in charter clause 3.b. The OpenBao TSC chairs may be non-TSC members: they will not have voting powers in OpenBao TSC matters and merely be a representative of the OpenBao TSC to the OpenSSF.

While charter clause 2.g implies that TSC Chair appointments are indefinite barring replacement ("will serve until their resignation or replacement by the TSC"), it is suggested that the TSC Chair position be re-approved by the TSC members every year, even if no replacement is desired.

## Membership Termination & Renewal

Membership lasts for a period of 2 years from approval, or for founding TSC members, 2 years from the approval of the TSC Charter (June 13th, 2024). Members are subsequently eligible to re-apply indefinitely.

A member may opt to terminate their membership at any time, by sending an email to the [TSC mailing list](https://lists.openssf.org/g/openbao-tsc).

Under charter clause 8.a, removing a member may occur through 2/3rds vote of the existing TSC, subject to approval by OpenSSF.

## TSC Membership Size

It is suggested that the OpenBao TSC comprise at most 10-20 named members. If more valid applications are received, it is suggested that they be put on hold until a vacancy opens (when a seat is up for renewal or otherwise) and be considered then.

Unlike OpenHorizon, while the TSC may delegate specific activities to Working Groups, it is not the intention of this document to give individuals serving as Working Group Chairs a vote on TSC matters, unless they are also a TSC member.

## Adoption of this Proposal

Because this proposal clarifies the charter, providing process outlined in charter clause 2.c, this document can be approved by the TSC body, ahead of and not terminating the startup period, via 2/3rds majority vote, subject to quorum, per charter clause 8.a.

This proposal may later be amended by the TSC under similar means; 2/3rds majority vote, subject to quorum.
