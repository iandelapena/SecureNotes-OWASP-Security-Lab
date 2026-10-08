
# Vulnerability Findings — SecureNotes Week 13 Peer Review

| #   | OWASP 2025 code & name          | Where (route / line)                                  | How attacker abuses it                             | Your Fix (1 Line)                 |
| --- | ------------------------------- | ----------------------------------------------------- | -------------------------------------------------- | --------------------------------- |
| 1   | A01 — Broken Access Control     | /notes/{id} (132–138); /admin/users (152–161)         | Reads private notes; bypasses admin check.         | Check ownership and admin role.   |
| 2   | A02 — Security Misconfiguration | CORS config (31–37)                                   | Allows cross-origin requests from untrusted sites. | Restrict CORS to trusted origins. |
| 3   | A04 — Cryptographic Failures    | users/register (48–65, 103–110)                       | Database leak reveals plaintext passwords.         | Store salted password hashes.     |
| 4   | A05 — Injection                 | /login (113–117)                                      | SQL input can bypass login.                        | Use parameterized SQL.            |
| 5   | A07 — Authentication Failures   | /login; current_user (86–90, 113–122)                 | Guessed IDs impersonate users.                     | Use signed, expiring tokens.      |
| 6   | A10 — Exceptional Conditions    | exception handler (94–99)                             | Errors expose stack traces.                        | Return generic error responses.   |

## Reflection (3–4 sentences)

The A01 Broken Access Control vulnerability could cause the most damage
because it allows unauthorized access to private notes and user information.
This could lead to serious data breaches and privacy violations.
A05 SQL Injection is also dangerous because attackers may bypass authentication.
Proper access controls and secure database queries are essential to protecting
the application.
