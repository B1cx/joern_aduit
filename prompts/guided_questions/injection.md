## Injection (D1) — Guided Questions

For each candidate injection vulnerability, answer these questions with code evidence:

### SQL Injection
1. Is user input concatenated/interpolated into a SQL string without parameterization?
2. If parameterized queries are used, are ALL parameters bound (not just some)?
3. Are table names or column names dynamically constructed from user input?
4. For ORM queries: is raw SQL mode used? Are $-style placeholders used instead of #-style?

### Command Injection
1. Does user input reach system(), exec(), or equivalent without escaping?
2. Are shell metacharacters (;|&`$) filtered?
3. Is the command built as an array (safe) or a single string (dangerous)?

### LDAP Injection
1. Is user input used in LDAP filter construction without escaping?
2. Are special LDAP characters (*()\\) sanitized?

### Expression Language Injection (SpEL/OGNL/EL)
1. Is user input evaluated as an expression?
2. Is the expression parser in safe mode / sandboxed?
