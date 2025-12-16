# Threat Intelligence Feeds

This document outlines how to leverage threat intelligence feeds to enhance the WAF's security capabilities. By integrating with various open-source and community-driven feeds, we can proactively block malicious actors and emerging threats.

## Supported Threat Feeds

We are focusing on free and open-source feeds. The following tables list the feeds we have evaluated and plan to support. The status column indicates the current state of our ability to consume the feed.

### IP Address Feeds

| Feed Name                                                              | Status             | Notes                                     |
| ---------------------------------------------------------------------- | ------------------ | ----------------------------------------- |
| Abuse.ch - Feodo Botnet (O)                                            | OK                 |                                           |
| Abuse.ch - Palevo Worm (O)                                             | OK                 |                                           |
| Abuse.ch - Zeus Botnet (O)                                             | OK                 |                                           |
| Alien Vault - Reputation (O)                                           | Parsing Error      |                                           |
| Blocklist.de - Attacks on the Service Apache (O)                       | OK                 |                                           |
| Blocklist.de - REG-Bots, IRC-Bots or BadBots (Spamming) (O)            | OK                 |                                           |
| Blocklist.de - Brute-Force Website Logins (O)                          | OK                 |                                           |
| Blocklist.de - Attacks on the Service FTP (O)                          | OK                 |                                           |
| Blocklist.de - Attacks on the Service IMAP, SASL, POP3 (O)             | OK                 |                                           |
| Blocklist.de - IRC Botnet (O)                                          | OK                 | No Present Data                           |
| Blocklist.de - Attacks on the Service Mail, Postfix (O)                | OK                 |                                           |
| Blocklist.de - Brute-Force SIP, VOIP or Asterisk-Server Logins Attacks (O) | OK                 |                                           |
| Blocklist.de - Attacks on the Service SSH (O)                          | OK                 |                                           |
| Blocklist.de - Strong IPs (O)                                          | OK                 |                                           |
| CINSscore.com - The CI Army List (O)                                   | Collecting Error   | Can not access the link via our IP.       |
| Team Cymru - Bogons IP List (O)                                        | OK                 |                                           |
| DShield - AS Report (O)                                                | OK                 |                                           |
| DShield - Top 20 Attacking Class C (O)                                 | OK                 |                                           |
| Danger.rulez.sk - Brute Force Attack (Firewall) (O)                    | OK                 |                                           |
| Dragon Research Group - SSH Brute Force Attack (O)                     | OK                 |                                           |
| Dragon Research Group - VNC Brute Force Attack (O)                     | OK                 |                                           |
| Malc0de - Malware (O)                                                  | OK                 |                                           |
| Malware Group - Unknown (O)                                            | Collecting Error   | Resource Not Available                    |
| Malware Group - Proxy (O)                                              | Collecting Error   | Resource Not Available                    |
| OpenBL.org - Abuse Reporting and Blacklisting (O)                      | OK                 |                                           |
| Spamhaus - DROP (Don't Route Or Peer Lists) (O)                        | OK                 |                                           |
| Taichung Blacklist - Malicious Activities (O)                          | OK                 |                                           |
| Turris Greylist - Scanning Attack (O)                                  | OK                 |                                           |
| URLVir - Malware (O)                                                   | OK                 |                                           |
| Spamhaus CERT Insight Portal - Botnet (O)                              | Collecting Error   | No API Key                                |

### Domain Name Feeds

| Feed Name                                       | Status              | Notes                  |
| ----------------------------------------------- | ------------------- | ---------------------- |
| Abuse.ch (Feodo Botnet) (O)                     | OK                  | No Present Data        |
| Abuse.ch (Palevo Worm) (O)                      | OK                  |                        |
| Abuse.ch (Zeus Botnet) (O)                      | OK                  |                        |
| DShield - Suspicious Domains (O)                | OK                  |                        |
| Malwarebytes hpHosts - Malicious Activities (O) | OK                  |                        |
| Malc0de - Malware (O)                           | OK                  |                        |
| Malware Domains - Malware (O)                   | OK                  |                        |
| Malware Group - Unknown (O)                     | Collecting Error    | Resource Not Available |
| URLVir - Malware (O)                            | OK                  |                        |
| DGArchive - Malware (O)                         | OK                  | Fix the collector      |
| n6stomp - Malicious Activities (O)              | Collecting Error    | No API Key             |

### URL Feeds

| Feed Name                               | Status              | Notes                   |
| --------------------------------------- | ------------------- | ----------------------- |
| CleanMX.de - Malware (O)                | OK                  |                         |
| CleanMX.de - Phishing (O)               | OK                  |                         |
| Security Research - Ponmocup Botnet (O) | OK                  |                         |
| Malware Domain List - Malware (O)       | OK                  |                         |
| OpenPhish - Phishing (O)                | OK                  | Missing 'Target' column |
| VXVault - Malware (O)                   | OK                  |                         |
| Alien Vault OTX - Malicious Activities (O) | OK               |                         |
| Blueliv - Malicious Activities (O)      | Collecting Error    | URL Changed             |
| PhishTank - Phishing (O)                | OK                  |                         |

## Actionable Next Steps

1.  **Prioritize Working Feeds:** Focus initial integration efforts on feeds marked as "OK".
2.  **Address Errors:**
    *   For feeds with "Parsing Error" or "Collecting Error", we will need to develop custom collectors or parsers.
    *   Feeds requiring API keys will need to be evaluated to see if free keys are available or if we need to contact the provider.
3.  **Develop Integration Logic:** The `threat_intelligence.rs` file will be the central point for integrating this data. It will need to be updated to:
    *   Fetch and parse the data from the various feeds.
    *   Store the IP addresses, domains, and URLs in an efficient data structure for lookups (e.g., a hash set or a specialized trie).
    *   Provide functions for the WAF core logic to check incoming requests against this data.
4.  **Configuration:** A new section in our `config.toml` will be required to enable/disable threat intelligence feeds and to configure individual feeds (e.g., URLs, API keys).

This documentation provides a clear path forward for enhancing our WAF with valuable threat intelligence.