---
title: "My First Week as an OpenBao Mentee!"
description: "Sharing my first experiences as an OpenBao mentee."
slug: my-first-week-openbao-mentee
authors: FattiesPatties
tags:  [mentee]
---

![openbao-mentee-doodle](/img/mentee-blog.png)

## My Journey Begins
Hey everyone! I’m Fatima and I’m excited to share how my OpenBao journey started! I had been working on app development but was eager to break into the cybersecurity world. So I browsed through various open-source projects and stumbled upon OpenBao. The project’s purpose caught my interest and, of course, the little bao mascot sealed the deal so I decided to dive in and set it up.

While running OpenBao tests on my Mac, I ran into a minor compatibility error. Instead of getting frustrated, I saw it as an opportunity to contribute.  I submitted my first issue to the OpenBao repository, worked on a fix, and a few days later, my pull request (PR) was approved! The excitement of having my first merged PR got me motivated to try out another issue, which also got merged later! After lurking around the repo for a few days, my mentor, Alex reached out to me with this wonderful opportunity and that is how my OpenBao journey began! 

<!-- truncate -->

## My First Week as a Mentee

My mentor and I discussed a few project ideas and issues I could pick up via mail, namely, implementing PQC (Post Quantum Cryptography) into OpenBao, ACME TLS listeners, improvements to the PKI (Public Key Infrastructure) role system, a role system for intermediate CAs and a few others.

I started off my week by picking a good first issue, [#459](https://github.com/openbao/openbao/issues/459), which focuses on allowing revocation of expired certificates. To get a clear understanding of it, I dove into the documentation, explored related issues, and familiarized myself with the underlying use cases. Once I had a solid grasp of the problem, I started exploring the codebase, running tests, and reviewing field validation rules along with the CRL configuration.

The week ended with a call with my mentor, where I shared updates on the tasks I had completed, asked a few questions, and proposed the next issue I'd like to work on. Alex was incredibly helpful, guiding me through my queries and offering valuable insights. Overall, my first week went by pretty smoothly despite the usual jitters that come with starting something new.

## What’s Next?
My excitement to contribute to OpenBao only grows as I dive deeper into the project. I am still relatively new to Go, how PKI is used in industry and the repository, so my short term goal is to be able to understand the project by picking smaller issues and then eventually work my way to bigger features. I’m currently working on issues within the PKI system, with plans to enhance it further. There’s also potential to explore ACME TLS listeners or even delve into Post Quantum Cryptography down the line!

I am documenting my OpenBao journey via [project journals](https://github.com/fatima2003/OpenBao-Project-Journals/tree/main) which you can follow along to see my progress as a mentee!
