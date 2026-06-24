---
title: "Shifting Secrets Left with ControlPlane Enterprise for OpenBao - PlatformCon 2026"
description: "Blog of Alex's talk at PlatformCon 2026, describing the governance capabilities of the server-side workflow features of OpenBao."
slug: cipherboy-platformcon-26-talk
authors: cipherboy
tags: [community, conferences, talks]
---

Slides and content from Alex's PlatformCon 2026 talk, describing the governance capabilities of the server-side workflow feature of OpenBao.

For a video, see the Platform Engineering's [official YouTube channel](https://www.youtube.com/watch?v=p1QD6AzG7g4).

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-01.svg">
SVG rendering is not supported on your browser.
</object>

Welcome to Shifting Secrets Left with ControlPlane Enterprise for OpenBao. I’m Alex Scheel, Head of OpenBao Development at ControlPlane and a member of OpenBao’s Technical Steering Committee.

<!-- truncate -->

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-02.svg">
SVG rendering is not supported on your browser.
</object>

The question I want to pose to everyone is: how do you govern your secrets management solution today? Is enforcement of internal policies around, say, secret rotation automated? Can developers self-serve onboarding applications, following your organization’s best practices? In short: what is your total cost of ownership of your secrets management solution?

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-03.svg">
SVG rendering is not supported on your browser.
</object>

ControlPlane started as a consultancy in 2017 but grew into the product space with ControlPlane Enterprise for FluxCD and now ControlPlane Enterprise for OpenBao. We have experience with some of the most highly-regulated environments, including large banks and governments. And our ethos is around empowering organizations to sustainably adopt open source technology to improve their security posture. We regularly organize CTFs for KubeCon and are collaborators in open-source foundations like the Linux Foundation’s CNCF and OpenSSF.

FluxCD is a popular gitops tool, empowering developers to self-service delivery of applications within an organization. Supporting Flux has given us a good view of how application developers could also onboard to secrets management tooling and building products around open-source tools.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-04.svg">
SVG rendering is not supported on your browser.
</object>

A lot of our institutional experience is also around defending infrastructure from supply chain and runtime attacks. We’ve done threat modeling and pentesting for several banks and helped to prioritize and assure remediation. And we look to see where off-the-shelf open source integrations for technologies like SBOMs can augment an organization’s security with defense-in-depth. Partnering with upstream projects allows us to prioritize feature development for our customers when aligned with the community’s mutual needs.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-05.svg">
SVG rendering is not supported on your browser.
</object>

A key component of ControlPlane’s stack is quickly becoming OpenBao, a fork of HashiCorp’s Vault under the OpenSSF. OpenBao is an open-source secrets and identity manager, featuring everything from static and dynamic secrets to PKI and key management services. As a project, we aim to keep API compatibility with HashiCorp Vault for client applications, but to meaningfully improve the operator and developer experience. OpenBao has built towards parity with Vault Enterprise, enabling horizontal scalability similar to Performance Standby nodes in OpenBao v2.5, support for namespaces in OpenBao v2.3, and PKCS#11/HSM-backed auto-unseal in OpenBao v2.2.

Along the way, we’ve introduced novel features like configuration-driven declarative self-initialization, allowing fully automated deployments of new OpenBao instances and solving the day 0 provisioning problems with Terraform or OpenTofu. We’ve improved snapshot consistency through the use of storage transactions. And we’ve shipped configuration-driven OCI-based distribution and loading of external plugins. We also deeply integrate with the cloud native landscape, shipping OpenBao through Helm charts and integrating with many CNCF projects such as OpenTofu, CertManager, External Secrets Operator, and more.

OpenBao is a broad toolbox for platform engineers and security professionals to help developers secure their applications in development and production environments. And we’re actively innovating and improving the operator and developer experience.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-06.svg">
SVG rendering is not supported on your browser.
</object>

At ControlPlane, we’re providing assurance for organizations consuming OpenBao through our ControlPlane Enterprise for OpenBao product line. We offer hardened images with up-to-date security patching, support agreements with up to 24/7 SLAs, and adoption support via technical account architects and facetime with project maintainers. This allows us to sustainably invest in the upstream community without exposing your organization to vendor lock-in and relicensing rug-pulls.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-07.svg">
SVG rendering is not supported on your browser.
</object>

Now that you’ve had time to think about the question posed earlier... I'll answer it from our perspective. From working with our customers across major industry verticals, a lot of organizations have difficulty automating governance processes around the secrets management solutions. As a result, the problem has been pushed down to platform engineering teams and thus to developers.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-08.svg">
SVG rendering is not supported on your browser.
</object>

When we look at a broader landscape of tools that platform engineering teams provide and developers consume, there’s a lot of automation that developers have come to rely on.

For dependency scanning, there’s open source tools like Google’s OSV-Scanner or Snyk. For license scanning, there’s trivy. For automatic updates of packages and dependencies, there’s dependabot and renovate. Nearly every code forge includes secrets scanning, including GitHub and GitLab. And vulnerability analysis in first-party code is getting better than ever with new AI harnesses releasing daily.

But secrets management has stagnated. Governance of these tools is complex and there’s few automatic solutions for fully-featured tools like Vault.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-09.svg">
SVG rendering is not supported on your browser.
</object>

So, as a hot-fix, many customers of ours have built their own external systems for operating secrets managers. These bespoke systems look like custom services or piles of Terraform or OpenTofu modules to build out spaces for teams to manage secrets for their applications. Many of them have built custom integrations with compliance reporting frameworks as well. This requires time and money to support on top of contracts for the tool itself. And the work is duplicated across the entire industry.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-10.svg">
SVG rendering is not supported on your browser.
</object>

Often these systems take two primary forms: governance and compliance reporting.

Governance services sit in front of a secrets manager, between developers and applications and the backend tool. Some customers have gone as far as providing an API facade in front of the secrets manager, theoretically allowing portability in the future, but ensuring correct access aligning with organization’s policies. Others have built controls with a ticketing system, where developers request application onboarding and an administrator provisions it up manually or assisted with scripts.

As secrets are created and consumed, artifacts (in the form of Vault/OpenBao’s audit logging events) are produced, recording usage and rotation of secrets. On top of this, organizations build reporting tools, automating compliance and integrating with SIEM solutions for compromise detection.

A big risk with these tools is that they often rely on highly privileged identities to orchestrate the underlying secrets manager. If compromised, these can allow an attacker to have long-term persistent access and pivot broadly within the organization.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-11.svg">
SVG rendering is not supported on your browser.
</object>

Since a lot of global, organization policy enforcement cannot be easily automated with Vault, such as compliance with secret rotation periods, we find that there’s often a human in the loop to provision and review developer and application access to the secrets manager. This slows application development rather substantially.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-12.svg">
SVG rendering is not supported on your browser.
</object>

As a result of the slowed development, engineers will find alternatives.

Sometimes, friction is good to force a developer to consider whether a decision is best aligned with the requirements of the organization.

When it comes to adopting the organization’s preferred secrets manager for visibility and auditing, however, a fully paved path is useful to avoid developers choosing an easier but unknown option.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-13.svg">
SVG rendering is not supported on your browser.
</object>

Why? Because they are many readily available, easy-to-use alternatives.

Some developers will check secrets into Git, causing a security incident in the process unless they’re encrypted with a tool like SOPS. Many source code forges like GitHub and GitLab provide secrets management either directly or through encrypted variables, allowing developers to onboard pipelines to internal systems. Or sometimes developers will have access to a password manager, which they’ll use to store and share passwords with other team members and even manually add secrets to production systems.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-14.svg">
SVG rendering is not supported on your browser.
</object>

The result is secrets sprawl. An organization’s security team needs to spend more time finding secrets, remediating via rotation into a centralized secrets manager, and assuring any potential security exposures have been handled appropriately. Secrets sprawl is costly to an organization as it increases an attacker’s ability to pivot within an organization and cause lasting, sustained damage and it is costly to remediate as there’s nearly infinite ways in which anything but an organization’s preferred secrets manager can be used.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-15.svg">
SVG rendering is not supported on your browser.
</object>

So, ControlPlane has begun driving features in OpenBao to build governance and compliance reporting into the platform itself.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-16.svg">
SVG rendering is not supported on your browser.
</object>

Based on the workflow engine, OpenBao 2.6’s will start to enable platform engineering teams to natively extend the secrets manager with organization-defined paved-paths they can share with internal developers. This builtin configurability means that adoption of a secrets manager can be fully automatic and platform security teams know that an organization’s defined best practices are being followed.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-17.svg">
SVG rendering is not supported on your browser.
</object>

Using the new workflow engine, privileged operators can define profiles, or multi-request flows, that they can control access to via regular ACL policies. A great example of a use case would be provisioning a new application into OpenBao. Operators could:

1. Create a namespace, ensuring strict isolation with other applications and a common identifier for auditing.
2. Set up human authentication, giving broader access to other privileged operators but defining scoped policies for developers. Perhaps, write-only access to static secrets and the ability to configure dynamic secrets.
3. Set up application authentication, granting common access based on known kubernetes workload identities.
4. Set up default secrets engines, preferring organizational-approved dynamic secret sources like database and Kubernetes.

While application developers would have permission to adopt and use the database integrations, authentication and authorization is locked down to privileged platform operators, preventing by default the use of static secrets and guaranteeing default rotation times. A second workflow could enable platform operators to provision static secrets into an application namespace if requested.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-18.svg">
SVG rendering is not supported on your browser.
</object>

Alternatively, operators can define compliance workflows for assuring static secrets are periodically rotated. They can:

1. Scan all application namespaces
2. Read the KVv2 metadata, to find the last rotation date, and evaluate that against organization’s policies.
3. And output the report in a standard format for consumption by other tooling.

This is again authorized and audited with internal permissioning, ensuring that no broadly permissive tokens are used across accounts or access.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-19.svg">
SVG rendering is not supported on your browser.
</object>

On the whole, the new workflow system in OpenBao ensures:

- Ease of use for application developers is on par with other platforms and password managers as they can self-service onboarding, enabling a fully paved path using the organization’s preferred tool.
- There’s less pressure on SecOps teams, by saving time executing human-in-the-loop processes and minimizing secrets sprawl, saving time performing triage and remediation.
- Applications can be delivered faster and more securely, via automated onboarding.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-platformcon-26/Shifting-Left-Slide-20.svg">
SVG rendering is not supported on your browser.
</object>

If there are any inquiries about ControlPlane Enterprise for OpenBao or our other services at ControlPlane, feel free to reach out to us [at on our website](https://control-plane.io/contact/?inquiry=openbao). Thank you!
