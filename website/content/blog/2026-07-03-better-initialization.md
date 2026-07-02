---
title: "Dreaming of a Better User Experience for Shamir's"
description: "A blog outlining what a better user experience for Shamir's might look like and what advantages it might have for OpenBao."
slug: better-shamir-ux
authors: cipherboy
tags: [community, conferences, vision]
---

At [Open Source Summit North America](./2026-06-17-cipherboy-oss-na-26-talk.md),
I met [Dr. Justin Cappos](https://engineering.nyu.edu/faculty/justin-cappos),
professor at NYU and major OpenSSF contributor and working group lead, and
several of his students.

Along with broader discussions of how OpenBao and [gittuf](https://gittuf.dev/)
might integrate, we talked about Shamir's unsealing and its fundamental
problem: it is a side-effecting process with high-entropy results. You can
wrap it around a common dictionary, hex or base64 encoding, or other means to
make the key shares more consumable by humans, but the results will still be
complex and hard to input and store.

The problems I'm looking for a scheme to solve are two fold:

1. Secure storage of Shamir shares are hard. It effectively relies on another,
   externally secure system (whether physical or digital) to safely store. In
   [emergency scenarios](/community/rfcs/emergency-seal/), this is fine, but
   if Shamir's is in regular use, this can be cumbersome depending on whether
   systems are air gapped or similar.
2. We can't easily use declarative self-initialization as we required a
   side-effect-less initialization.

<!-- truncate -->

### On Shamir's

While I will spare people too much math, some initial context on why this is
non-trivial with Shamir's is important. For a conceptual model, think of
[Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
as using polynomial equations:

```
s + a_1 x_1 + a_2 x_2^2 + a_3 x_3 ^ 3 + ...
```

By convention, the secret is embedded as the constant term of this polynomial,
with constants (`a_1 ... a_n`) being randomly chosen values. To allow for a
threshold of `n+1` shares required to recover, a `n` degree polynomial must
be chosen. For two share recovery, a linear equation is used; for three shares
to recover, a quadratic, &c. This is because while `n+1` `(x, y)` points
uniquely describe a `n`-degree polynomial, `n` shares leaks no information:
nearly any possible constant term could fall out.

This gives Shamir's secret sharing an useful property: _information theoretic
security_.

:::info

The above is a simplification: left to the reader are discussions about
encoding secrets and the frequent implementation over finite fields rather
than the real numbers. Make sure to always use cryptographically secure
random number generators and do not roll your own crypto!

OpenBao has moved [our Shamir's implementation to
`sdk/`](https://pkg.go.dev/github.com/openbao/openbao/sdk/v2/helper/shamir)
so that others may consume it.

:::

### Requirements

Cappos proposed a model for Shamir's that worked by masking password hashes
with the Shamir shares (via an xor); but in our context, we would mask Shamir
shares with password hashes. Supposing such a scheme could exist, we'd care
about the following properties:

1. It isn't _much_ more computationally expensive. Shamir's is easy to verify:
   combining the pieces and performing a decryption of the root key using the
   recovered AES-GCM key is relatively cheap.
2. It doesn't have side effects: we can't require the owner to know which Shamir
   share a given password maps to.
3. It retains the core cryptographic properties of Shamir's when used in our
   barrier encryption scheme: thresholds, arbitrary share ordering, &c must
   all be retained.
4. Storage of shares must be safe in plaintext. Because this is the root of
   our cryptography, we don't have any other secure storage mechanism
   available yet.
5. Hinted at above, but passwords and shares must be independent. While the
   security of the scheme as a whole will be dictated by the combined entropy
   of the (threshold-determined) weakest passwords, we can put system limits
   on their construction. Passwords shouldn't derive into shares and thus have
   unexpected determinism: we'd want strictly independent root keys to allow
   for rotation under the same passwords.

:::info

_Aside_: Actual security depends on the details of this scheme and what
definition of "isn't much more computationally expensive" is used. Certain
variants provide more security (sum of weakest passwords) whereas others are
faster to verify at the cost less security (strength of nth weakest password).
Balancing that trade-off will probably depend on use cases; if you're
interested, feel free to [reach out](https://github.com/openbao#contact) to
us and mention the blog!

:::

### Results

Assuming such a scheme existed, this would give us a great way to extend our
side-effect free [declarative self-initialization](/docs/configuration/self-init)
to Shamir's seal mechanisms:

1. Operators would establish configuration like they do for auto-unseal
   devices and namespace sealing, specifying the number of generated shares
   and thresholds. This could perhaps be denoted via a new seal type,
   `shamir-pass` or similar.
2. Operators could optionally specify minimum password complexity rules using
   our existing [password policies](/docs/concepts/password-policies), which
   support validating against existing passwords.
3. We have two options for how initialization could go:

   - We could either immediately initialize, requiring operators to
     authenticate with any provisioned authentication provider and then
     subsequently only allow initialization requests (blocking broader
     requests to the system) to provide the required passwords until
     concluded.

   - Or, we could delay self-initialization until sufficient passwords have
     been provided, following the existing (unauthenticated) initialization
     or rotation patterns.

   Notably, neither of these two approaches would yield keys to the API
   callers which must be stored.

Within namespace sealing, we would already have an authenticated rotation
mechanism and be able to reuse that for initialization.

From an unseal perspective, this also makes it easier for air-gapped operators
wanting to use Shamir's to type and unseal OpenBao.
