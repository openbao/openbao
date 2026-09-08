---
title: "Sustainable Secrets Management with OpenBao - Open Source@Siemens 2026"
description: "Blog of Michael's talk at Open Source @ Siemens 2026, diving into OpenBao's origins and why it is the sustainable choice."
slug: karras-os-siemens-2026-talk
authors: karras
tags: [community, conferences, talks]
---

Slides and content from Michael's talk at Open Source @ Siemens 2026, diving
into OpenBao's origins and why it is the sustainable choice.

For a video, see Siemens' [official YouTube channel](https://www.youtube.com/watch?v=hPBT-kSS-68).

---

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-01.svg">
SVG rendering is not supported on your browser.
</object>

Welcome everyone to my talk on OpenBao and sustainable secrets management! I'm
Michael "Hofi" Hofer, CTO at Adfinis and Chair of the OpenBao Technical
Steering Committee (TSC).

It's fantastic to be back here in Zug for Open Source @ Siemens - for me
personally, this event is always an annual highlight. Huge thanks to the
Siemens crew for organizing such a great event! Every year it gets better, and
this time we even have romantic ambient lighting to go with it. I'm already
looking forward to next year.

Also, a quick shout-out to Jan and Pasquale for the [overview on
CIP](https://www.youtube.com/watch?v=R87uGvXzK7g) earlier. It's really cool to
see a neighboring Linux Foundation project in action.

Today I want to share how we can ensure secrets management remains open,
community-driven, and sustainable for decades to come.

<!-- truncate -->

---

### What is Secrets Management?

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-02.svg">
SVG rendering is not supported on your browser.
</object>

Before we jump into OpenBao itself, let's briefly step back: what do we
actually mean when we talk about *secrets management*?

Looking around the room, I know most of you have strong technical backgrounds,
so the core concept isn't new. It's the daily practice of protecting and
integrating all the secrets your machine workloads need to function - API
tokens, TLS certificates, credential pairs, and client secrets.

Notice I said *machine workloads*. We don't focus on human passwords here;
those belong in a proper password manager. But for machine identities, the bar
is high: your secrets management solution needs to be super secure and highly
available. But just as importantly, it has to be flexible and
developer-friendly. Our main audience consists of engineering teams who just
want a solution that works without getting in their way.

---

### Why is Secrets Management relevant for you?

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-03.svg">
SVG rendering is not supported on your browser.
</object>

In my day-to-day conversations with community members and technicial teams, the
reasons to invest in secrets management usually boil down to three main
drivers:

First, **cybersecurity and risk mitigation**. We've all seen secrets sprawl -
static database credentials or Kubernetes tokens committed into repos and never
rotated. If you come back to an environment three years later and find the
exact same root password sitting on every VM, that's a problem. Compliance
regulations like the Cyber Resilience Act (CRA) and audit flags are also paying
into that.

Second, **efficiency**. Nobody wants to get an X.509 certificate delivered via
email or pasted into a Slack channel, forcing you to become a manual secrets
manager yourself when you'd rather be writing code.

And third, **saving money**. Many proprietary cybersecurity products on the
market carry immense license fees, making cost predictability a massive
headache.

---

### Challenges in the Secrets Management ecosystem

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-04.svg">
SVG rendering is not supported on your browser.
</object>

Looking at secrets management today, technical teams want modern,
well-integrated platforms, while organizations need data sovereignty because
these systems hold their crown jewels.

Yet, proprietary vendors often force what we call an **"Architecture by
License."** You design your secrets management platform according to a
contract, instead of your actual needs to avoid exploding license costs.

How many of you have had a developer ask to onboard a new pipeline or
Kubernetes cluster, only to be told: *"Sorry, we don't have the budget for
those additional licenses this year"*? It forces us to ask: Is there no
sustainable, open alternative left?

---

### OpenBao is the answer

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-05.svg">
SVG rendering is not supported on your browser.
</object>

Well, of course there is - and that's why OpenBao is here!

---

### What is OpenBao?

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-06.svg">
SVG rendering is not supported on your browser.
</object>

So, what is OpenBao? At its core, OpenBao is a modern, open source secrets
management solution designed to handle the full spectrum of security needs:

* **Static and Dynamic Secrets:** From moving static KV keys into a central
  store to generating short-lived database credentials or cloud identities that
  are automatically revoked.

* **PKI & Certificate Management:** Replacing manual certificate workflows with
  automated internal CAs and ACME integration.

* **Key Management & Cryptography-as-a-Service:** Offloading encryption,
  decryption, and signing operations directly to OpenBao APIs so your
  applications don't have to handle raw keys.

OpenBao is hosted under the **Linux Foundation (OpenSSF)**. It was forked from
HashiCorp Vault in late 2023 under the open MPL-2.0 license.

Now, here's an interesting side story: does anyone know who was one of the main
driving forces and founders behind initiating the fork?

It was actually IBM. They were heavily invested in the Open Horizon project
under LF Edge, which relied on Vault. When Vault's license changed, they helped
launch and drive the fork under the Linux Foundation (right around the same
time Terraform was forked into OpenTofu).

Unfortunately, those IBM colleagues got pulled out of the OpenBao project when
IBM acquired HashiCorp a few months later. Though we'd welcome them back
anytime.

Most importantly, it remains **largely API compatible**. If you have a tool,
client library, or solution with a "Vault supported" stamp, there is a very
high chance it will work with OpenBao out of the box.

---

### By and for the community

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-07.svg">
SVG rendering is not supported on your browser.
</object>

One thing I want to make clear: OpenBao is not a single-vendor project. It's
built by and for the community.

We have a fantastic, healthy maintainer base of roughly 15 to 20 co-maintainers
actively working on the project every single day. A massive **thank you** to
all of them and to our wider community!

Our governance is completely transparent, managed by the Technical Steering
Committee (TSC) under the OpenSSF. We have colleagues from (alphabetically)
**Adfinis, ControlPlane, GitLab, IOTech, SAP, WALLIX**, and independent
maintainers driving the project forward together. Multi-vendor governance is
essential for true open source sustainability. It ensures no single vendor can
pull the rug out or change the rules on you later.

---

### The OpenBao ecosystem is growing!

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-08.svg">
SVG rendering is not supported on your browser.
</object>

A few months ago, we decided to launch an [ecosystem page](/ecosystem/) on
openbao.org to show who is using, adopting, and integrating with OpenBao. Since
then, the ecosystem page has taken off faster than we anticipated!

We have ISVs, HSM manufacturers, cloud service providers, and security vendors
like Nitrokey, NVIDIA, Crypto4A, OVHcloud, Utimaco, Percona, Securosys,
Sigstore, and others listed. Seeing this real-world adoption proves that
OpenBao is rapidly becoming a trusted standard for production workloads.

---

### Commercial sustainability

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-09.svg">
SVG rendering is not supported on your browser.
</object>

Now, allow me a quick word on how Adfinis, for example, makes this sustainable
from a business perspective. We heard about open source budgets from the
previous talk by the CIP project, and at Adfinis we faced the same question:
How do we fund full-time upstream development on OpenBao for years to come?

Our answer was productizing **Secretz Enterprise** - an enterprise subscription
providing 24/7 enterprise support, software assurance, and continuous
development for OpenBao.

We built this model to be **vendor lock-in free** while mitigating the "Success
Tax", where you get penalized for growth with a per-identity pricing model. If
a customer ever cancels their subscription, their production clusters keep
running without a hitch. There are no artificially gated features, no
per-identity limits, and no hidden license keys. Everything we build goes
upstream first.

In a similar manner [other vendors in the ecosystem](/ecosystem/vendors/) are
also invested in order to build a sustainable business model to support OpenBao
in the long run.

---

### Recent and unique features

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-10.svg">
SVG rendering is not supported on your browser.
</object>

OpenBao isn't just maintaining a fork. We are actively adding features that our
community has been asking for, including:

* **PostgreSQL Storage Backend:** Offering PostgreSQL as a storage option
  alongside the widely adopted Raft backend for organizations with established
  database footprints.

* **Declarative Operator Workflows:** Introducing declarative
  self-initialization, declarative plugin distribution via OCI images, and
  declarative audit devices to make deployments as smooth as possible.

* **Namespaces:** Shipping multi-tenant namespace isolation out of the box.

* **Horizontal Read Scalability:** Released in version 2.5, allowing standby
  nodes to serve read requests directly, paving the way for many more such
  capabilities.

---

### Project and development direction

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-11.svg">
SVG rendering is not supported on your browser.
</object>

Where are we heading next? We divide our priorities into two streams:

**Project Direction:** We are focused on community growth, moving from the
OpenSSF Sandbox to the Incubation stage, launching our Marketing Working Group,
and filling documentation gaps with user and operator guides.

**Development Direction:** Just to name a few of the many additional cool
capabilities, including External Keys, Seal Pluginization and Per-Namespace
Sealing (shipped in 2.6), or a dedicated provider for the External Secrets
Operator.

---

### How to contribute and join the community?

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-12.svg">
SVG rendering is not supported on your browser.
</object>

If you're interested in checking out OpenBao or want to get involved, we would
love to have you! Head over to
[openbao.org/community](/community):

* **Join the Chat:** Jump into our Zulip chat channel or drop into our open
  community calls.
* **GitHub:** Open issues, start discussions, or send PRs on
  [github.com/openbao/openbao](https://github.com/openbao/openbao).
* **Working Groups:** Participate in dedicated groups around development,
  security, or marketing.
* **Get Listed:** If your organization is using OpenBao, open a PR to add your
  logo to our ecosystem page!

---

### Contribute and win!

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-13.svg">
SVG rendering is not supported on your browser.
</object>

We don't quite have a fancy contributor store like GitLab just yet, but we do
have some cool swag to give away!

The first three people who submit **3 mergeable pull requests** adhering to our
contribution guidelines can email me at `michael.hofer@adfinis.com` to claim
their prize:

* **1st Place:** OpenBao Bricks Kit
* **2nd Place:** OpenBao T-Shirt
* **3rd Place:** OpenBao Stickers

*Note: Existing project and TSC members are excluded to keep it fair for new
contributors!*

---

### Let's collaborate!

<object type="image/svg+xml" data="/img/talks/karras-os-siemens-2026/Sustainable-Secrets-Management-Slide-14.svg">
SVG rendering is not supported on your browser.
</object>

Thank you so much for your time today, and thanks again to Siemens for hosting
OpenBao here in Zug!
