# EU Regulatory Status (validated 2026-10-31)

This note records the EU rules that the compliance module maps to. It is
engineering context, **not legal advice or a certification**. Check the
consolidated legal text and your national implementation before relying on it.

## EU AI Act

- **Legal base:** Regulation (EU) 2024/1689, as amended by **Regulation (EU)
  2026/1744** (Digital Omnibus on AI), OJ 24 July 2026, in force 27 July 2026.
- **Current timeline:**
  - 2 February 2025: prohibitions and AI-literacy duties.
  - 2 August 2025: general-purpose AI obligations.
  - 27 July 2026: amending regulation in force; sectoral provisions apply.
  - **2 August 2026: general application, including Article 50 transparency.**
  - **2 December 2026:** new Article 5 prohibitions (non-consensual intimate
    imagery/CSAM) and Article 50(2) for synthetic content already on the market.
  - **2 December 2027:** high-risk Annex III obligations (previously 2 August 2026).
  - **2 August 2028:** Annex I embedded high-risk obligations (previously 2 August 2027).
  - 2 August 2030: public-authority use obligations.
- **What this means for WAF-Rejected:** the proxy is not an AI system by itself.
  The AI/ML threat-detection modules are experimental and disabled by default.
  If a deployment adds AI functionality, the provider must perform its own
  classification, conformity assessment, transparency and record-keeping.
- **Evidence the WAF can provide:** audit/security event history, configuration
  change history, integrity hashes, retention controls.
- **Do not claim:** AI Act conformity, CE marking, or “AI Act compliant” from
  `generate_ai_act_report()`.

Sources:

- https://eur-lex.europa.eu/eli/reg/2024/1689/oj
- https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng
- https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai

## NIS2

- **Legal base:** Directive (EU) 2022/2555. Transposition deadline was
  17 October 2024; NIS1 was repealed from 18 October 2024.
- **Status at 2026-10-31:** national transposition remains uneven. The
  Commission's official transposition page records Court of Justice referrals
  against member states for incomplete notification. Verify the law of each
  member state where the service is offered.
- **Amendment proposals:** on 20 January 2026 the Commission proposed targeted
  NIS2 amendments (simplification and alignment with the Cybersecurity Act).
  The separate Digital Omnibus data file was still a proposal in October 2026;
  the Council adopted its negotiating mandate on 21 October 2026, but Parliament
  had not adopted its position, so trilogues had not started. **Current NIS2
  obligations are unchanged.**
- **Incident cascade to validate with the relevant CSIRT:**
  - early warning within 24 hours of awareness;
  - incident notification within 72 hours;
  - final report within one month.
- **What this means for WAF-Rejected:** security events and blocking decisions
  are useful detection evidence, but they do not by themselves satisfy NIS2.
  Scope, registration, supply-chain duties, management accountability and
  national reporting channels remain organisation-specific.
- **Evidence the WAF can provide:** high/critical security events, source IPs,
  timestamps, rule matches, retention and audit integrity.
- **Do not claim:** “NIS2 compliant” from `generate_nis2_report()`.

Sources:

- https://eur-lex.europa.eu/eli/dir/2022/2555
- https://digital-strategy.ec.europa.eu/en/policies/nis2-directive
- https://digital-strategy.ec.europa.eu/en/policies/nis-transposition

## Cyber Resilience Act (CRA)

- **Legal base:** Regulation (EU) 2024/2847.
- **Status at 2026-10-31:**
  - **11 September 2026: Article 14 reporting obligations are in force** for
    manufacturers of products with digital elements.
  - **11 December 2027:** main essential cybersecurity requirements, conformity
    assessment and CE marking apply.
  - Open-source software stewards have reporting obligations from
    11 December 2027.
- **Article 14 cascade (ENISA CRA Single Reporting Platform):**
  - early warning within 24 hours of awareness;
  - full notification within 72 hours;
  - final report within 14 days of a corrective measure for an actively
    exploited vulnerability, or within one month for a severe incident.
- **What this means for WAF-Rejected:** if the project is supplied as a product
  with digital elements on the EU market, manufacturer duties may apply. The
  repository now ships a coordinated vulnerability disclosure policy
  ([`SECURITY.md`](../../SECURITY.md)), a support-period and patch policy
  ([`docs/operations/support-policy.md`](../operations/support-policy.md)) and a
  CycloneDX SBOM on every tagged release. Automated SRP submission is still not
  implemented.
- **Evidence the WAF can provide:** actively exploited vulnerability indicators,
  severe incident events, timestamps, affected deployment identity.
- **Do not claim:** “CRA compliant” or automatic Article 14 reporting. Submission
  to ENISA/CSIRT is manual and organisation-specific.

Sources:

- https://eur-lex.europa.eu/eli/reg/2024/2847/oj
- https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp

## Other frameworks already modelled

The compliance module also has GDPR, HIPAA and PCI-DSS report formats. Those
reports are evidence packs, not certifications. The previous “COMPLIANT” label
in the PCI report was replaced with “EVIDENCE GENERATED - ASSESSMENT REQUIRED”.

## Complementary tooling

The companion project [Transparenz](https://transparenz.fyi/) targets the CRA
operational workflow (SBOMs, vulnerability evidence, ENISA SRP reporting and
audit evidence). WAF-Rejected should supply Article 14 detection evidence to
that workflow rather than duplicate the reporting lifecycle.

## Configuration

```toml
[security.compliance.regulatory]
gdpr = true
ai_act = true
nis2 = true
cra = true
```

The `compliance` Cargo feature must be enabled to compile the module.
