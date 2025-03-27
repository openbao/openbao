---
title: "OpenBao Adopted as the Secret Store for EdgeX Foundry"
description: "Why EdgeX chose OpenBao for its critical secret storage"
slug: edgex-selects-openbao
authors: JamesButcher
tags: [announcement, community, collaboration]
image: https://www.edgexfoundry.org/cmsfiles/image/company-logo-lg.png
---

Great news for the OpenBao community! In a major step towards enhancing its own security and openness, EdgeX Foundry has officially adopted OpenBao as its default secret store for the EdgeX 4.0 release.

## What is EdgeX Foundry?
For those unfamiliar, [EdgeX Foundry](https://www.edgexfoundry.org/) is an open-source, IoT/edge computing framework hosted by the Linux Foundation. It’s designed to enable seamless communication between devices, applications and services using a flexible, microservices-based architecture. Whether you’re working in automation, energy, or building management, EdgeX helps bring everything together in a standardized way.

![edgex-logo](https://www.edgexfoundry.org/cmsfiles/image/company-logo-lg.png)

<!-- truncate -->

## The Need for Secret Storage
Security is a top priority in EdgeX, and managing secrets—like API keys, passwords, and certificates—is crucial. Instead of reinventing the wheel, EdgeX has always integrated third-party open-source solutions for secret management. Until now, it relied on HashiCorp Vault for securely storing sensitive information.

However, with Vault moving to a Business Source License (BSL), the EdgeX community wanted to consider an alternative going forward. That’s where OpenBao comes in.

## The Role of OpenBao
OpenBao is a community-driven, open-source project under the Linux Foundation. It provides an identity-based secrets and encryption management system, ensuring sensitive data stays protected. Since it shares a strong foundation with Vault, OpenBao makes for a natural transition.

## Why OpenBao?
Adopting OpenBao brings several advantages to EdgeX Foundry, including:

✅ Seamless Migration – OpenBao is designed to be API compatible with its upstream, making the switch smooth and hassle-free.

✅ Open & Vendor-Neutral Licensing – open-source freedom and long-term community collaboration.

✅ Security-First Approach – Strong encryption and identity-based access controls keep secrets safe.

✅ Active Community Support – A dedicated team ensures ongoing improvements, security updates and feature enhancements.

## What this means for EdgeX Users
If you’re already using EdgeX, this change should be practically seamless. The Core Services have been updated to work with OpenBao while keeping the same APIs as before, meaning minimal disruption. You’ll still manage secrets securely, with the added benefit of an actively maintained and community-driven solution.

## Looking Ahead
The move to OpenBao reflects EdgeX Foundry’s ongoing dedication to security, transparency, and open-source collaboration. With EdgeX 4.0 (codenamed Odesa) now released, it is the perfect time to explore OpenBao, share feedback, and get involved in shaping its future.

Stay tuned for more updates on OpenBao and [keep in touch with EdgeX](https://github.com/orgs/edgexfoundry/discussions) and related commercial products, as they enjoy the benefits of security and openness with OpenBao going forward!
