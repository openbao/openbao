---
title: "OpenBao @ GitLab - FOSDEM '25"
description: "Blog of Alex's talk at FOSDEM '25, describing the usage of OpenBao at GitLab"
slug: cipherboy-fosdem-25-talk
authors: cipherboy
tags: [community, conferences, talks]
---

Slides and content from Alex's [FOSDEM '25 talk](/blog/fosdem-25) about OpenBao's usage at GitLab.

For a video, see our [official YouTube channel](https://youtu.be/V50hdX2d8IA) or [on the FOSDEM video mirror](https://video.fosdem.org/2025/ua2118/fosdem-2025-5145-openbao-at-gitlab-building-native-secrets-for-gitlab-ci-cd-pipelines.av1.webm).

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-01.svg">
SVG rendering is not supported on your browser.
</object>


Hello everyone! I'm Alex Scheel, a Staff Backend Engineer at GitLab and Chair of the OpenBao Technical Steering Committee. I'm here to talk about OpenBao and its usage at GitLab.

<!-- truncate -->

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-02.svg">
SVG rendering is not supported on your browser.
</object>

To get started, the most important question is, "What is OpenBao"?

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-03.svg">
SVG rendering is not supported on your browser.
</object>


OpenBao is a fork of HashiCorp Vault, remaining under the original Mozilla Public License, with open governance under the Linux Foundation's LF Edge subproject.

It is an advanced secrets manager supporting four categories of features:

1. _Static secrets_, provisioned by users directly and securely stored.
2. _Dynamic secrets_, automatically generated on-demand to integrate with things like databases or cloud provider identities.
3. _Encryption services_, supporting PKI or SSH certificate creation and KMS-like encryption-as-a-service functionality.
4. And lastly, _Sync, Visibility, and Management_ of these secrets: integrations with Kubernetes External Secret Operator, Cert-Manager, and a custom templating agent to handle last-mile delivery of secrets. All of this comes with detailed audit logs tracking access to the system.

A secrets manager is, to organizations and developers writing applications, what a password manager is for humans.

OpenBao is API-driven and highly flexible. It supports many different authentication engines, from OIDC and Kubernetes to LDAP and Kerberos, and creating or storing many types of identities, letting it function as an _identity broker_.

The goal is to trade-off a little bit of _operational risk_ -- one more, admittedly complex, service to run -- to greatly lessen the _security risk_ of compromise: you can enforce a healthy secrets posture to ensure that rotation and revocation of sensitive credentials are possible, limiting your organization's exposure window in the event of compromise.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-04.svg">
SVG rendering is not supported on your browser.
</object>


While a complete timeline of OpenBao would take a while, there's a few important events I want to highlight:

 - HashiCorp first released Vault in April of 2015, so there has been nearly a decade of work on it.
 - In August of 2023, HashiCorp announced that they'd be relicensing their products under the non-OSI Business Source License (violating freedom zero); this triggered the early fork of Terraform into OpenTofu, our sister project also under the Linux Foundation.
 - The fork of Vault by IBM Software came much later, in November of that year, and kept with the naming convention. Unlike OpenTofu, which was made up of many member companies which sponsored full-time development, OpenBao has been more of a grass-roots, community effort.
 - We've done 8 releases -- two major and six bug fixes, shipped several core improvements, and put together our Technical Steering Committee and governing documents.
 - My employer, GitLab, joined the project officially in July and achieved voting status in October of last year. To the best of my knowledge, I'm incredibly fortunate to be one of the few people employed to work on OpenBao full time.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-05.svg">
SVG rendering is not supported on your browser.
</object>


One of the things you might be asking is, OK, it is another fork of a HashiCorp product. What's different about this one?

While OpenBao remains in the spirit of the original project, we've made a few changes to make it easier to maintain and contribute:

1. We started with a reduced base, removing many components that an open-source group with no formal funding could not support. That meant making hard choices around storage backends -- Raft and now PostgreSQL are the only supported two -- but also the removal of proprietary cloud integrations for authentication and dynamic secrets for the time being. We hope to revive especially the cloud auth and secret plugins as we get more funding and interest.
2. Using that space, we've made core technological improvements to the storage subsystem--paginated lists and transactions--which in turn allowed us to improve scalability. These improvements were directly made possible by removing every single storage backend but Raft. We hope these types of improvements will continue after we add APIs for additional external, community-provided storage plugins, so that we can make long-term improvements to upcoming features like namespaces and horizontal scalability.
2. Lastly, we've set up an open organization with clear contribution and project leadership processes. Our RFC process is open to anyone to draft designs and propose major or minor changes to the architecture or project. We've started a community mentorship program, helping two individuals with different familiarity with OpenBao to contribute. But throughout this, we continued under the original MPL license.

In short, my personal vision for where I hope OpenBao can go is to build an ecosystem similar to Kubernetes: companies large and small, and individuals experienced or just starting out, can contribute to the project and find market segments to provide derivative offerings while contributing to a common code base.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-06.svg">
SVG rendering is not supported on your browser.
</object>


Next, you might be asking "why GitLab"?

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-07.svg">
SVG rendering is not supported on your browser.
</object>


For a while, GitLab has been focused on building a more complete DevSecOps platform.

A common problem our customers face is managing secrets in their CI/CD Pipelines. Today, they have one of two options:

1. They can use masked variables. These have very few controls over the scope of access and customers can't easily differentiate in the dashboard between secrets and inconsequential data, though all are stored encrypted at rest. A few customers have many thousands of variables and the difference in ideal behavior differs substantially between the two use cases for them. No one solution will really work for both.
2. Instead, many customers turn to our external integrations with various other secret management providers. However, the user experience isn't quite there: one typically has to work across several teams to enable OIDC ID Token authentication so pipelines can access secrets and the customer must organize the logistics of secret storage and rotation. Because GitLab plays a very minor role, mostly by providing identity to the pipelines, it lacks visibility into the actual secrets and the hierarchy administrators have set up.

In short, there is no easy-to-use, per-project dashboard for secrets and neither approach can provide this easily. And many times, a developer has to find many individuals in their organization with permissions to do one of these steps in order to onboard their new project.

In late 2023, GitLab started working on this problem, building their own design from the ground up. In May, my colleague, Jocelyn, published this in a blog post, considering the use of OpenBao to solve this problem.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-08.svg">
SVG rendering is not supported on your browser.
</object>


OpenBao is a great choice for GitLab because we already support a HashiCorp Vault integration. For Premium and Ultimate tier customers, the Pipeline runner features native integration for fetching secrets from Vault: while all GitLab versions support issuing the OIDC ID Tokens, these paid plans offer support for a simplified pipeline syntax, improving the developer experience over manual CLI calls to Vault.

Being a mature secrets management solution already, OpenBao brings several useful properties to GitLab:

1. It has already been deployed at scale by various entities.
2. It has historically undergone audits and certifications useful for enterprise customers.
3. It is a self-contained service, which we can isolate from the rest of our environment and treat as trusted.

What we'd like to do is provide a single dashboard which lets us aggregate information into a project-specific view of secrets. Whereas previously audit logs might be separate between GitLab and a backend Vault instance, we can correlate them natively within the GitLab UI. Or, where access controls required understanding two separate permissions models--that of GitLab and that of Vault's ACL policies--GitLab will translate its own roles into OpenBao policies on behalf of the user.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-09.svg">
SVG rendering is not supported on your browser.
</object>


At its core, our architecture is just like it was before, but with OpenBao replacing HashiCorp Vault and moving it from the customer's deployment to our management scope. It remains a separate service that pipeline workers talk to and customers will eventually be able to bring their own KMS to secure key material as well.

What is new is the interactions, typically driven by a user, between Rails and OpenBao for management purposes. When a user initiates any secrets management
request, they do so via GitLab's Rail's API, which enforces initial authentication and holds privileged tokens for ACL management. In the future, we seek to add a User JWT issuer, allowing direct secret write operations by users without invoking Rails.

We thus get a clean trust separation, between three different entities:

1. GitLab Rails, which will perform various administrative actions on behalf of users,
2. Pipelines, which will execute jobs and fetch secrets, and
3. OpenBao, which is the source of truth for authorization and secret storage.

With official PostgreSQL support, OpenBao will be able to use the same database as Rails for smaller self-managed GitLab instances, avoiding the complexities of managing Raft which come with running Vault. Data will be encrypted before storing it in PostgreSQL and requires keys from a seal mechanism to decrypt.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-10.svg">
SVG rendering is not supported on your browser.
</object>


The key to integrating OpenBao is to be opinionated about its data storage layout. Philosophically, OpenBao aligns with key/value databases: its API path structure usually mirrors the underlying data storage. ACL policies are groups of grants to specific capabilities–like read, write, delete–on specific API paths, with a default deny rule. After authentication, perhaps via a third-party engine, OpenBao issues a token, mapping an identity to a set of ACL policies. Thus, there is no concept of a long-term identity which has ownership of a secret.

The core of our design to integrate with OpenBao is a data layout which provides multi-tenancy and isolation of secrets. This architecture is familiar to many of our customers who have successfully integrated with their HashiCorp Vault clusters.

Each top-level tenant, usually the owner of a repository, has a separate path area in OpenBao. Within this space, they have an authentication mount for authorizing pipeline's access to secrets, with roles corresponding to each project. Each project has its own KVv2 secrets engine for storing that project's secrets, which contains custom metadata indicating the scope and contextual information like description.

GitLab Rails can read this metadata and provision ACL policies and JWT roles for all scopes when changes are necessary.

When support for Namespaces lands upstream, we'll seek to provision each tenants into their own namespaces and, long-term, we wish to use unique encryption keys with separate seal mechanisms to provide greater data isolation on GitLab.Com via per-tenant encryption keyrings.

Within the core management space is another authentication mount for authorizing Rail's own requests into OpenBao. The core of these requests are for provisioning new tenants and their mounts but also being the trusted entity that maintains the ACL policies. These ACL policies reflect the permissions and scopes of access designated by users for accessing these secrets: each environment or branch for a project is a separate policy, which contains read access to secrets within that scope.

Authentication occurs via a properties based model. OIDC ID Tokens issued by GitLab to pipeline jobs have claims reflecting contextual metadata, such as the repository, branch, initiating user, and environment. Each tenant's JWT mount matches these claims to a per-project role, with dynamic generation of ACL policies based on the properties present on the token.

Uniquely, this model lets us use OpenBao as the single source of truth for all operations: permissions are reflected via ACL roles, scopes and context are present in contextual metadata, and Rails is only present as a management engine and a trusted token issuer and pipeline provisioner and does not store data of its own.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-11.svg">
SVG rendering is not supported on your browser.
</object>


So from a developer's perspective, all this work leads to the following two actions to use secrets in their pipelines:

1. Create a new secret via the native GitLab UI, specifying the scope of access and its value.
2. Access the secret from a pipeline's `.gitlab-ci.yml` definition file, using the secret name as the reference key.

And GitLab Rails and OpenBao will handle the rest.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-12.svg">
SVG rendering is not supported on your browser.
</object>


At GitLab, we've been really excited about using OpenBao. If you are too, we welcome contributors of any sort! You can check out our roadmap, join our weekly community calls, or talk about OpenBao on social media or at conferences.

If you're a customer interested in the work GitLab is doing to build our native pipeline secrets solution, ask your account team about joining our beta program.

---

<object type="image/svg+xml" data="/img/talks/cipherboy-fosdem-25/OpenBao-at-GitLab-Slide-13.svg">
SVG rendering is not supported on your browser.
</object>


I'm happy to take questions now, but if you have any additional questions or want stickers or a picture with our cute mascot, BaoBao, find me afterwards in person or online!
