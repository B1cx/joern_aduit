package knowledge

// CWEEntry describes a CWE vulnerability class with useful metadata.
type CWEEntry struct {
	ID          string   `json:"id"`          // e.g. "CWE-89"
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`    // typical: CRITICAL, HIGH, MEDIUM, LOW
	Categories  []string `json:"categories"`  // rule category keywords (SQLI, CMDI, etc.)
	Mitigations []string `json:"mitigations"` // common defense patterns
	References  []string `json:"references"`  // URLs
}

// CWEDatabase is an in-memory CWE knowledge base.
type CWEDatabase struct {
	entries    map[string]*CWEEntry // keyed by CWE ID
	categories map[string]string    // category keyword → CWE ID
}

// NewCWEDatabase creates and populates the CWE knowledge base.
func NewCWEDatabase() *CWEDatabase {
	db := &CWEDatabase{
		entries:    make(map[string]*CWEEntry),
		categories: make(map[string]string),
	}
	db.populate()
	return db
}

// Lookup returns a CWE entry by ID.
func (db *CWEDatabase) Lookup(cweID string) *CWEEntry {
	return db.entries[cweID]
}

// LookupByCategory returns the CWE entry for a rule category keyword.
func (db *CWEDatabase) LookupByCategory(category string) *CWEEntry {
	if cweID, ok := db.categories[category]; ok {
		return db.entries[cweID]
	}
	return nil
}

// ResolveCWE maps a rule ID (e.g. "JAVA-SQLI-001") to a CWE ID.
func (db *CWEDatabase) ResolveCWE(ruleID string) string {
	// Extract category from rule ID: JAVA-SQLI-001 → SQLI
	parts := splitRuleID(ruleID)
	if len(parts) >= 2 {
		if cweID, ok := db.categories[parts[1]]; ok {
			return cweID
		}
	}
	return "CWE-UNKNOWN"
}

// AllEntries returns all CWE entries.
func (db *CWEDatabase) AllEntries() []*CWEEntry {
	result := make([]*CWEEntry, 0, len(db.entries))
	for _, e := range db.entries {
		result = append(result, e)
	}
	return result
}

func splitRuleID(ruleID string) []string {
	var parts []string
	current := ""
	for _, c := range ruleID {
		if c == '-' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func (db *CWEDatabase) populate() {
	entries := []CWEEntry{
		{
			ID:          "CWE-89",
			Name:        "SQL Injection",
			Description: "The application constructs SQL statements from user-controlled input without proper neutralization, allowing attackers to modify query logic.",
			Severity:    "CRITICAL",
			Categories:  []string{"SQLI"},
			Mitigations: []string{
				"Use parameterized queries / PreparedStatement",
				"Use ORM frameworks with built-in escaping",
				"Input validation with whitelist approach",
				"Stored procedures with parameterized inputs",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/89.html",
				"https://owasp.org/www-community/attacks/SQL_Injection",
			},
		},
		{
			ID:          "CWE-78",
			Name:        "OS Command Injection",
			Description: "The application constructs OS commands from user-controlled input, allowing execution of arbitrary system commands.",
			Severity:    "CRITICAL",
			Categories:  []string{"CMDI"},
			Mitigations: []string{
				"Avoid OS command execution with user input",
				"Use language-level APIs instead of shell commands",
				"Strict whitelist validation of allowed commands",
				"Filter shell metacharacters (;|&$`\\n)",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/78.html",
			},
		},
		{
			ID:          "CWE-94",
			Name:        "Code Injection",
			Description: "The application allows user input to be interpreted as code (eval, template injection, expression language injection).",
			Severity:    "CRITICAL",
			Categories:  []string{"RCE", "SSTI", "EL"},
			Mitigations: []string{
				"Never evaluate user input as code",
				"Use sandboxed template engines",
				"Disable dangerous template features",
				"SecurityManager for script engine execution",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/94.html",
			},
		},
		{
			ID:          "CWE-79",
			Name:        "Cross-Site Scripting (XSS)",
			Description: "The application includes user-controllable data in web output without proper encoding, enabling script injection.",
			Severity:    "HIGH",
			Categories:  []string{"XSS"},
			Mitigations: []string{
				"Context-aware output encoding (HTML, JS, URL, CSS)",
				"Content Security Policy (CSP) headers",
				"Use framework auto-escaping (e.g., Thymeleaf, React)",
				"HttpOnly/Secure cookie flags",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/79.html",
			},
		},
		{
			ID:          "CWE-918",
			Name:        "Server-Side Request Forgery (SSRF)",
			Description: "The application makes HTTP requests to URLs specified by user input, allowing access to internal services.",
			Severity:    "HIGH",
			Categories:  []string{"SSRF"},
			Mitigations: []string{
				"URL allowlist for permitted destinations",
				"Block private/internal IP ranges",
				"Disable HTTP redirects or limit redirect targets",
				"Use a dedicated proxy for outbound requests",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/918.html",
			},
		},
		{
			ID:          "CWE-22",
			Name:        "Path Traversal",
			Description: "The application uses user input to construct file paths without proper validation, allowing access to arbitrary files.",
			Severity:    "HIGH",
			Categories:  []string{"LFI", "FILE", "UPLOAD"},
			Mitigations: []string{
				"Canonicalize paths and validate against base directory",
				"Use allowlist of permitted file names",
				"Reject paths containing .. or absolute path components",
				"chroot or sandboxed file system access",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/22.html",
			},
		},
		{
			ID:          "CWE-502",
			Name:        "Deserialization of Untrusted Data",
			Description: "The application deserializes data from untrusted sources, enabling arbitrary code execution via gadget chains.",
			Severity:    "CRITICAL",
			Categories:  []string{"DESER"},
			Mitigations: []string{
				"Avoid native Java serialization of untrusted data",
				"Use allowlist-based ObjectInputStream filters (JEP 290)",
				"Prefer JSON/XML with schema validation",
				"Remove unnecessary gadget chain libraries from classpath",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/502.html",
			},
		},
		{
			ID:          "CWE-611",
			Name:        "XML External Entity (XXE)",
			Description: "The application parses XML input with external entity processing enabled, allowing file disclosure or SSRF.",
			Severity:    "HIGH",
			Categories:  []string{"XXE"},
			Mitigations: []string{
				"Disable DTD processing entirely",
				"Set FEATURE_SECURE_PROCESSING on XML parsers",
				"Disable ACCESS_EXTERNAL_DTD and ACCESS_EXTERNAL_SCHEMA",
				"Use JSON instead of XML where possible",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/611.html",
			},
		},
		{
			ID:          "CWE-287",
			Name:        "Improper Authentication",
			Description: "The application fails to properly verify the identity of a user, allowing unauthorized access.",
			Severity:    "CRITICAL",
			Categories:  []string{"AUTH"},
			Mitigations: []string{
				"Use established authentication frameworks",
				"Implement multi-factor authentication",
				"Secure session management (random tokens, timeouts)",
				"Hash passwords with bcrypt/scrypt/Argon2",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/287.html",
			},
		},
		{
			ID:          "CWE-285",
			Name:        "Improper Authorization",
			Description: "The application fails to properly enforce access controls, allowing users to access resources beyond their privileges.",
			Severity:    "HIGH",
			Categories:  []string{"AUTHZ", "IDOR"},
			Mitigations: []string{
				"Implement role-based access control (RBAC)",
				"Verify authorization on every request (not just UI)",
				"Use indirect object references instead of direct IDs",
				"Principle of least privilege",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/285.html",
			},
		},
		{
			ID:          "CWE-327",
			Name:        "Use of Broken Cryptographic Algorithm",
			Description: "The application uses weak or deprecated cryptographic algorithms (MD5, SHA1, DES, RC4).",
			Severity:    "MEDIUM",
			Categories:  []string{"CRYPTO"},
			Mitigations: []string{
				"Use AES-256-GCM for symmetric encryption",
				"Use SHA-256 or SHA-3 for hashing",
				"Use RSA-2048+ or ECDSA for asymmetric operations",
				"Follow NIST SP 800-131A guidelines",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/327.html",
			},
		},
		{
			ID:          "CWE-90",
			Name:        "LDAP Injection",
			Description: "The application constructs LDAP queries from user input without proper sanitization.",
			Severity:    "HIGH",
			Categories:  []string{"LDAP"},
			Mitigations: []string{
				"Escape special LDAP characters in user input",
				"Use parameterized LDAP search filters",
				"Validate input against expected patterns",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/90.html",
			},
		},
		{
			ID:          "CWE-643",
			Name:        "XPath Injection",
			Description: "The application constructs XPath queries from user input without proper sanitization.",
			Severity:    "HIGH",
			Categories:  []string{"XPATH"},
			Mitigations: []string{
				"Use parameterized XPath queries",
				"Validate and escape user input",
				"Use compiled XPath expressions",
			},
			References: []string{
				"https://cwe.mitre.org/data/definitions/643.html",
			},
		},
	}

	for i := range entries {
		entry := &entries[i]
		db.entries[entry.ID] = entry
		for _, cat := range entry.Categories {
			db.categories[cat] = entry.ID
		}
	}
}
