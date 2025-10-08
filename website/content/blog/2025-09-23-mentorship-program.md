---
title: "The Perfectly Unperfect Mentorship"
description: "No blueprint, no problem. How a 12-week experiment in guided chaos delivered a performance breakthrough."
slug: mentorship-program
authors: AndriiFedorchuk
tags: [mentorship, community, opensource, collaboration]
---

Imagine starting a mentorship program with a big goal and... not a perfect plan. Sound familiar? That was us, three months ago. We had a brilliant mentee, [**Fatima Patel**](https://github.com/fatima2003), a crucial feature for OpenBao’s roadmap, and a healthy dose of "let's figure this out as we go."

Spoiler alert: it worked. Spectacularly. But not because we had all the answers on day one. It worked because we treated the mentorship itself like an open-source project: we iterated, adapted, and optimized for success in real-time.

This is the story of how we structured—and restructured—a 12-week program that ended up giving OpenBao a scalability boost and fantastic contributions.

#### **The Setup: An Experiment with High Stakes**

The goal was ambitious: transform OpenBao’s **passive standby nodes** into **active cluster participants** that can handle read requests, a key step towards horizontal scalability. [**Adfinis**](https://www.adfinis.com/) provided the crucial fuel by funding the program, and the initiative was kicked off by [**Alexander Scheel**](https://github.com/cipherboy), who created [the project on the LFX Mentorship Platform](https://mentorship.lfx.linuxfoundation.org/project/d419da30-b718-435d-8673-6c1260307339).

My role was to be the primary mentor. This was a shared investment: Adfinis invested funds and my time, while Fatima invested her talent and immense effort.

We started with a hypothesis: intensive, daily collaboration would be the fastest way to onboard her into the complex codebase.

#### **The Rhythm of Mentorship: Finding Our Flow**

For the first few weeks, we met **every single day for an hour**. This intensive pace was essential for building context and momentum. But we quickly learned that the magic wasn't just in the meetings—it was in the deep, uninterrupted work happening in between.

So, we adapted. Around the halfway mark, we shifted our rhythm to **three meetings per week**. This wasn't a step back; it was a strategic pivot. The focus moved away from daily "what do we do next?" check-ins to structured sessions where we could define clear tasks for the upcoming week. This gave Fatima the autonomy for deep, focused work and essential self-teaching, while ensuring she always had support to overcome obstacles.

And the support team grew! In the second part of the program, Fatima had the fantastic opportunity to work closely with [**Philipp Stehle**](https://github.com/phil9909) from Adfinis, who was tackling cache invalidation challenges between nodes. This turned the mentorship into a true team collaboration. Instead of one mentor, she effectively had two, which was an incredible advantage and made the experience much more dynamic.

#### **The Mentee’s Lens: Lessons Beyond the Code**

>From my side of the screen, this mentorship was more than a 12-week coding sprint — it taught me the importance of confidence, perseverance and how collaboration and adapting strategies as new problems arise are essential parts of working effectively in a team.
>
>When we initially discussed horizontal scalability as the topic for the mentorship, I remember feeling underprepared, having never worked in that space before. My mentor, [Andrii](https://github.com/driif)’s uplifting encouragement and guidance helped me dive in, understand the problem space, and start experimenting with solutions. Once [Philipp](https://github.com/phil9909) joined the project, the pace picked up and the discussions became even more engaging.
>
>The community also held bi-monthly meetings led by [Alex](https://github.com/cipherboy) to review progress on high availability and discuss next steps. These sessions ensured the work stayed aligned with the community’s goals and that our progress moved in the right direction.
>
>Looking back, the experience shaped not just how I write code, but how I approach challenges — with curiosity, collaboration, and confidence!

#### **The 12-Week Sprint: A Choice We'd Make Again**

The LFX platform offers 12-week full-time or 24-week part-time programs. We’re incredibly glad Fatima chose the **12-week option**. It forced a healthy intensity—a focused sprint that kept everyone laser-focused on the goal: delivering a tangible, impactful feature for the community.

And what a feature it was. Under this adapted structure, Fatima’s contributions were profound:
*   She enabled **standby nodes to handle read requests**, a fundamental shift from idle replicas to active participants.
*   She implemented the **post-unsealing logic**, ensuring standbys are fully initialized and ready to work.

The result? A foundational improvement that makes OpenBao clusters more efficient and performant. Standby nodes are no longer resource-consuming fallback insurance; they are now part of the active workforce.

#### **The Real Win: A Model for Community-Led Growth**

This program was a win on every level.
*   **For OpenBao:** We gained a critical feature from our roadmap and a valuable contributor.
*   **For Fatima:** She tackled a complex project with direct, high-impact outcomes and the support of a collaborative team.
*   **For [Adfinis](https://www.adfinis.com/):** The investment in funding and our time directly contributed to the health of an open-source project we believe in.

The real success wasn't just the code. It was proving that with the right combination of **funding, flexibility, and a team spirit**, you can structure a mentorship to achieve incredible things. It’s about creating a focused environment where a talented developer, like [**Fatima Patel**](https://github.com/fatima2003), can deeply integrate with a maintainer's workflow to accelerate complex, high-impact projects that benefit the entire community.

This is how we build a sustainable open-source future: not by waiting for perfect plans, but by creating opportunities, adapting as we go, and investing in people.

**Want to learn more about the technical outcomes?** Check out the pull requests and join the conversation on our [OpenBao GitHub repository](https://github.com/openbao/openbao).

**Inspired to get involved?** Explore the [LFX Mentorship Platform](https://mentorship.lfx.linuxfoundation.org/project/d419da30-b718-435d-8673-6c1260307339) and see how you can contribute.
