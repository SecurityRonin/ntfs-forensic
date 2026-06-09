//! Built-in triage questions for rapid incident response.
//!
//! Questions are ordered by urgency — what a panicked incident commander
//! needs to tell the CEO in 10 minutes. Business-outcome first, technical
//! detail underneath.
//!
//! ## Question order
//!
//! 1-3:  "What happened?" — initial access, malware, execution proof
//! 4-6:  "How bad is it?" — data access, staging, credentials
//! 7-8:  "Are we still at risk?" — persistence, lateral movement
//! 9-11: "Did they cover tracks?" — evidence destruction, timestomping, disguise
//! 12:   "What did we recover?" — carved/ghost records (populated by report generator)
