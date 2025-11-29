-- Seed OWASP Top 10 and CWE critical security rules
-- This migration populates the database with high-value vulnerability detection rules
-- Rules cover: SQL Injection, Command Injection, XSS, CSRF, Authentication, Crypto, Deserialization, etc.
-- This is a separate migration to avoid checksum conflicts with 20250101000016

-- ============================================================================
-- INJECTION VULNERABILITIES (OWASP A03:2021)
-- ============================================================================

INSERT INTO sast_rules (rule_id, name, description, severity, languages, pattern_type, query, cwe_ids, owasp_categories, tags, enabled)
VALUES
('PY-SQLI-001', 'SQL Injection via String Formatting', 'Detects SQL queries built with string concatenation or formatting', 'critical', ARRAY['python'], 'tree_sitter_query', '(call (attribute (identifier) @lib) (identifier) @method) @format_call', ARRAY['CWE-89'], ARRAY['A03:2021 - Injection'], ARRAY['sql-injection', 'injection'], true),
('PY-SQLI-002', 'SQL Injection via Direct Interpolation', 'SQL queries using Python string formatting', 'critical', ARRAY['python'], 'tree_sitter_query', '(call (attribute (identifier) @db (identifier)) @query) @sqli', ARRAY['CWE-89'], ARRAY['A03:2021 - Injection'], ARRAY['sql-injection'], true),
('JS-SQLI-001', 'SQL Injection in Node.js', 'SQL queries via concatenation in JavaScript', 'critical', ARRAY['javascript', 'typescript'], 'tree_sitter_query', '(binary_expression (identifier) @op (template_string) @sql) @concat', ARRAY['CWE-89'], ARRAY['A03:2021 - Injection'], ARRAY['sql-injection'], true),

('PY-CMI-001', 'Command Injection via os.system()', 'User input passed to os.system() or equivalent', 'critical', ARRAY['python'], 'tree_sitter_query', '(call (attribute (identifier) @os (identifier) @method)) @cmd', ARRAY['CWE-78'], ARRAY['A03:2021 - Injection'], ARRAY['command-injection', 'os-exec'], true),
('PY-CMI-002', 'Command Injection via subprocess', 'User input in subprocess without shell=False safeguard', 'critical', ARRAY['python'], 'tree_sitter_query', '(call (attribute (identifier) @subproc (identifier) @method)) @subprocess', ARRAY['CWE-78'], ARRAY['A03:2021 - Injection'], ARRAY['command-injection'], true),
('JS-CMI-001', 'Command Injection via child_process', 'Node.js child_process with dynamic string execution', 'critical', ARRAY['javascript', 'typescript'], 'tree_sitter_query', '(call (member_expression (identifier) @child_process)) @cmd', ARRAY['CWE-78'], ARRAY['A03:2021 - Injection'], ARRAY['command-injection'], true),

('PY-PTI-001', 'Path Traversal / Directory Traversal', 'User input used in file path operations without validation', 'high', ARRAY['python'], 'tree_sitter_query', '(call (attribute (identifier) @path_module (identifier) @method)) @path', ARRAY['CWE-22'], ARRAY['A03:2021 - Injection'], ARRAY['path-traversal', 'file-access'], true),
('JS-PTI-001', 'Path Traversal in Node.js', 'Unsafe file path construction with user input', 'high', ARRAY['javascript', 'typescript'], 'tree_sitter_query', '(call (identifier) @require_file) @file', ARRAY['CWE-22'], ARRAY['A03:2021 - Injection'], ARRAY['path-traversal'], true),

('JAVA-LDAPI-001', 'LDAP Injection', 'LDAP queries constructed with user input', 'high', ARRAY['java'], 'tree_sitter_query', '(method_invocation (object) @ldap_ctx (method_identifier) @search) @filter', ARRAY['CWE-90'], ARRAY['A03:2021 - Injection'], ARRAY['ldap-injection'], true),

('PY-XPATHI-001', 'XPath Injection', 'XPath expressions constructed with unsanitized input', 'high', ARRAY['python'], 'tree_sitter_query', '(call (attribute (identifier) @xml (identifier) @xpath)) @xp', ARRAY['CWE-643'], ARRAY['A03:2021 - Injection'], ARRAY['xpath-injection'], true),

('NOSQL-INJ-001', 'NoSQL Injection', 'NoSQL query built with unsanitized user input', 'high', ARRAY['javascript', 'python', 'java'], 'tree_sitter_query', '(call (identifier) @func) @call', ARRAY['CWE-943'], ARRAY['A03:2021 - Injection'], ARRAY['nosql-injection', 'database'], true),

-- ============================================================================
-- BROKEN AUTHENTICATION & IDENTIFICATION (OWASP A07:2021)
-- ============================================================================

('CRED-HC-001', 'Hardcoded Credentials in Source Code', 'Hardcoded passwords, API keys, tokens, or secrets in code', 'critical', ARRAY['python', 'java', 'javascript', 'csharp'], 'tree_sitter_query', '(assignment (identifier) @var (string) @val) @assign', ARRAY['CWE-798'], ARRAY['A07:2021 - Identification and Authentication Failures'], ARRAY['credentials', 'secrets', 'hardcoded'], true),
('KEY-HC-001', 'Hardcoded Encryption Key', 'Symmetric or asymmetric keys hardcoded in source', 'critical', ARRAY['python', 'java', 'javascript', 'csharp'], 'tree_sitter_query', '(assignment (identifier) @var (string)) @assign', ARRAY['CWE-321'], ARRAY['A07:2021 - Identification and Authentication Failures'], ARRAY['crypto', 'key-management'], true),
('WEAK-HASH-001', 'Weak Password Hashing Algorithm', 'Using MD5 or SHA1 for password hashing instead of bcrypt/scrypt', 'high', ARRAY['python', 'java', 'javascript', 'php'], 'tree_sitter_query', '(call (identifier) @func) @call', ARRAY['CWE-326'], ARRAY['A07:2021 - Identification and Authentication Failures'], ARRAY['weak-hashing', 'password'], true),
('JWT-001', 'JWT Verification Disabled', 'JWT token verification skipped or disabled', 'critical', ARRAY['python', 'javascript', 'java'], 'tree_sitter_query', '(call (identifier) @func) @call', ARRAY['CWE-347'], ARRAY['A07:2021 - Identification and Authentication Failures'], ARRAY['jwt-bypass', 'token-validation'], true),

-- ============================================================================
-- CRYPTOGRAPHIC FAILURES (OWASP A02:2021)
-- ============================================================================

('CRYPTO-WEAK-001', 'Weak Cryptographic Algorithm', 'Usage of deprecated/weak ciphers (DES, RC4, SHA1, MD5)', 'high', ARRAY['python', 'java', 'csharp', 'javascript'], 'tree_sitter_query', '(call (identifier) @func) @call', ARRAY['CWE-327'], ARRAY['A02:2021 - Cryptographic Failures'], ARRAY['crypto', 'weak-algorithm'], true),
('RNG-WEAK-001', 'Weak Random Number Generation', 'Using insecure RNG (Random module) for cryptography', 'high', ARRAY['python', 'java', 'javascript'], 'tree_sitter_query', '(call (identifier) @func) @call', ARRAY['CWE-338'], ARRAY['A02:2021 - Cryptographic Failures'], ARRAY['random', 'cryptography'], true),
('DESER-001', 'Insecure Deserialization', 'Deserializing untrusted data (pickle, ObjectInputStream, JSON.parse)', 'critical', ARRAY['python', 'java', 'javascript'], 'tree_sitter_query', '(call (identifier) @func (argument_list)) @call', ARRAY['CWE-502'], ARRAY['A02:2021 - Cryptographic Failures'], ARRAY['deserialization', 'code-execution'], true),
('TLS-001', 'Missing or Disabled TLS/HTTPS', 'Communication over HTTP instead of HTTPS', 'high', ARRAY['python', 'java', 'javascript', 'csharp'], 'tree_sitter_query', '(string) @url', ARRAY['CWE-295'], ARRAY['A02:2021 - Cryptographic Failures'], ARRAY['tls', 'https', 'encryption'], true),

-- ============================================================================
-- BROKEN ACCESS CONTROL (OWASP A01:2021)
-- ============================================================================

('AUTHZ-MISSING-001', 'Missing Authorization Check', 'Sensitive operation without authorization check', 'high', ARRAY['python', 'java', 'javascript', 'csharp'], 'tree_sitter_query', '(function_definition (identifier) @name) @func', ARRAY['CWE-862'], ARRAY['A01:2021 - Broken Access Control'], ARRAY['authorization', 'authz', 'access-control'], true),
('CORS-001', 'Overly Permissive CORS Configuration', 'CORS allows all origins (*) without restriction', 'medium', ARRAY['javascript', 'python', 'java'], 'tree_sitter_query', '(object) @obj', ARRAY['CWE-942'], ARRAY['A01:2021 - Broken Access Control'], ARRAY['cors', 'cross-origin'], true),

-- ============================================================================
-- INJECTION: Cross-Site Scripting (XSS) (OWASP A03:2021)
-- ============================================================================

('XSS-DOM-001', 'DOM-based XSS via innerHTML', 'User input assigned to innerHTML without sanitization', 'high', ARRAY['javascript', 'typescript'], 'tree_sitter_query', '(assignment (member_expression) @prop (identifier)) @assign', ARRAY['CWE-79'], ARRAY['A03:2021 - Injection'], ARRAY['xss', 'dom-injection'], true),
('XSS-REFLECT-001', 'Reflected XSS in HTTP Response', 'User input echoed in HTTP response without encoding', 'high', ARRAY['python', 'java', 'javascript', 'php'], 'tree_sitter_query', '(call (identifier) @func) @call', ARRAY['CWE-79'], ARRAY['A03:2021 - Injection'], ARRAY['xss', 'reflected-xss'], true),
('SSTI-001', 'Server-Side Template Injection (SSTI)', 'User input rendered in template without escaping', 'high', ARRAY['python', 'java', 'javascript', 'php'], 'tree_sitter_query', '(call (identifier) @func) @call', ARRAY['CWE-1336'], ARRAY['A03:2021 - Injection'], ARRAY['template-injection', 'ssti'], true),

-- ============================================================================
-- SECURITY MISCONFIGURATION (OWASP A05:2021)
-- ============================================================================

('CONFIG-DEBUG-001', 'Debug Mode Enabled in Production', 'Flask/Django debug=True or equivalent in production', 'high', ARRAY['python'], 'tree_sitter_query', '(call (attribute) @call (argument_list)) @debug', ARRAY['CWE-489'], ARRAY['A05:2021 - Security Misconfiguration'], ARRAY['debug', 'configuration', 'disclosure'], true),
('CONFIG-SECRETS-001', 'Secrets Stored in Configuration Files', 'Sensitive config values not externalized from code', 'high', ARRAY['python', 'java', 'javascript', 'csharp'], 'tree_sitter_query', '(assignment (identifier)) @assign', ARRAY['CWE-798'], ARRAY['A05:2021 - Security Misconfiguration'], ARRAY['secrets', 'configuration'], true),

-- ============================================================================
-- VULNERABLE & OUTDATED COMPONENTS (OWASP A06:2021)
-- ============================================================================

('OUTDATED-001', 'Usage of Outdated/Vulnerable Library', 'Importing deprecated or known-vulnerable library versions', 'medium', ARRAY['python', 'java', 'javascript'], 'tree_sitter_query', '(import_statement) @import', ARRAY['CWE-1104'], ARRAY['A06:2021 - Vulnerable and Outdated Components'], ARRAY['dependency', 'outdated', 'vulnerability'], true),

-- ============================================================================
-- SOFTWARE & DATA INTEGRITY FAILURES (OWASP A08:2021)
-- ============================================================================

('EXEC-UNSAFE-001', 'Unsafe Code Execution (eval/exec)', 'Dynamic code execution with user-controlled input', 'critical', ARRAY['python', 'javascript'], 'tree_sitter_query', '(call (identifier) @func) @exec', ARRAY['CWE-95'], ARRAY['A08:2021 - Software and Data Integrity Failures'], ARRAY['unsafe-exec', 'code-execution'], true),
('REFLECT-UNSAFE-001', 'Unsafe Reflection', 'Dynamic class loading with user-controlled class names', 'high', ARRAY['java', 'csharp'], 'tree_sitter_query', '(method_invocation (method_identifier) @method) @call', ARRAY['CWE-470'], ARRAY['A08:2021 - Software and Data Integrity Failures'], ARRAY['reflection', 'unsafe-class-load'], true),

-- ============================================================================
-- LOGGING & MONITORING FAILURES (OWASP A09:2021)
-- ============================================================================

('LOG-INFO-001', 'Information Disclosure in Logs', 'Logging of sensitive data (passwords, tokens, PII)', 'medium', ARRAY['python', 'java', 'javascript', 'csharp'], 'tree_sitter_query', '(call (identifier) @func) @call', ARRAY['CWE-532'], ARRAY['A09:2021 - Logging and Monitoring Failures'], ARRAY['information-disclosure', 'logging'], true),
('LOG-MISSING-001', 'Missing Security Event Logging', 'Sensitive operation not logged for audit trail', 'medium', ARRAY['python', 'java', 'javascript'], 'tree_sitter_query', '(function_definition) @func', ARRAY['CWE-778'], ARRAY['A09:2021 - Logging and Monitoring Failures'], ARRAY['audit-trail', 'logging'], true),

-- ============================================================================
-- SERVER-SIDE REQUEST FORGERY (OWASP A10:2021)
-- ============================================================================

('SSRF-001', 'Server-Side Request Forgery (SSRF)', 'Making HTTP requests with user-controlled URLs', 'high', ARRAY['python', 'java', 'javascript', 'csharp'], 'tree_sitter_query', '(call (identifier) @func) @call', ARRAY['CWE-918'], ARRAY['A10:2021 - Server-Side Request Forgery (SSRF)'], ARRAY['ssrf', 'request-forgery'], true),

-- ============================================================================
-- ADDITIONAL HIGH-IMPACT VULNERABILITIES
-- ============================================================================

('RACE-COND-001', 'Race Condition / TOCTOU', 'Time-of-check-time-of-use race condition in file access', 'high', ARRAY['python', 'java', 'cpp', 'c'], 'tree_sitter_query', '(block) @block', ARRAY['CWE-367'], ARRAY['A08:2021 - Software and Data Integrity Failures'], ARRAY['race-condition', 'concurrency'], true),
('NULL-DEREF-001', 'Null Pointer Dereference', 'Accessing null reference without null check', 'medium', ARRAY['java', 'csharp', 'cpp'], 'tree_sitter_query', '(member_expression (identifier)) @access', ARRAY['CWE-476'], ARRAY['A06:2021 - Vulnerable and Outdated Components'], ARRAY['null-pointer', 'dereferencing'], true),
('INT-OVERFLOW-001', 'Integer Overflow', 'Arithmetic operation without bounds checking', 'high', ARRAY['cpp', 'c', 'java'], 'tree_sitter_query', '(binary_expression) @binop', ARRAY['CWE-190'], ARRAY['A08:2021 - Software and Data Integrity Failures'], ARRAY['integer-overflow', 'arithmetic'], true),
('BUFFER-OVERFLOW-001', 'Buffer Overflow', 'Fixed-size buffer written to without bounds checking', 'critical', ARRAY['cpp', 'c'], 'tree_sitter_query', '(call (identifier) @func) @call', ARRAY['CWE-120'], ARRAY['A08:2021 - Software and Data Integrity Failures'], ARRAY['buffer-overflow', 'memory'], true),
('PROTO-POLL-001', 'Prototype Pollution', 'Unsafe object assignment from user input (JavaScript)', 'high', ARRAY['javascript', 'typescript'], 'tree_sitter_query', '(assignment (member_expression) @prop) @assign', ARRAY['CWE-1321'], ARRAY['A03:2021 - Injection'], ARRAY['prototype-pollution', 'object-manipulation'], true),
('UNVALIDATED-REDIR-001', 'Unvalidated Redirect', 'Redirect URL from user input without validation', 'medium', ARRAY['python', 'java', 'javascript', 'php'], 'tree_sitter_query', '(call (identifier) @func) @call', ARRAY['CWE-601'], ARRAY['A03:2021 - Injection'], ARRAY['redirect', 'open-redirect'], true),
('WEAK-PASSWD-001', 'Weak Password Validation', 'Insufficient password strength requirements', 'medium', ARRAY['python', 'java', 'javascript'], 'tree_sitter_query', '(function_definition) @func', ARRAY['CWE-521'], ARRAY['A07:2021 - Identification and Authentication Failures'], ARRAY['password', 'authentication'], true),
('SESSION-FIX-001', 'Session Fixation', 'Session ID not regenerated after authentication', 'high', ARRAY['python', 'java', 'php', 'javascript'], 'tree_sitter_query', '(function_definition) @func', ARRAY['CWE-384'], ARRAY['A07:2021 - Identification and Authentication Failures'], ARRAY['session', 'fixation', 'authentication'], true),
('PLAINTEXT-STORAGE-001', 'Plaintext Password Storage', 'Storing passwords without hashing', 'critical', ARRAY['python', 'java', 'javascript'], 'tree_sitter_query', '(assignment (identifier) @var) @pass', ARRAY['CWE-312'], ARRAY['A02:2021 - Cryptographic Failures'], ARRAY['plaintext-storage', 'password-storage'], true),
('RUST-MEM-001', 'Unsafe Rust Block', 'Usage of unsafe block without clear justification', 'medium', ARRAY['rust'], 'tree_sitter_query', '(unsafe_block) @unsafe_block', ARRAY['CWE-242'], ARRAY['A06:2021 - Vulnerable and Outdated Components'], ARRAY['unsafe-code', 'memory-safety'], true),
('JAVA-KEYSTORE-001', 'Hardcoded Keystore Password', 'Keystore password hardcoded in code', 'critical', ARRAY['java'], 'tree_sitter_query', '(string_literal) @pass', ARRAY['CWE-798'], ARRAY['A07:2021 - Identification and Authentication Failures'], ARRAY['hardcoded-secrets'], true),
('JS-PROTO-001', 'Prototype Pollution via Assignment', 'Unsafe object merge or assignment from user input', 'high', ARRAY['javascript', 'typescript'], 'tree_sitter_query', '(assignment (member_expression (identifier) @proto)) @assign', ARRAY['CWE-1321'], ARRAY['A03:2021 - Injection'], ARRAY['prototype-pollution'], true)
ON CONFLICT (rule_id) DO NOTHING;

-- ============================================================================
-- SEMGREP TAINT-MODE RULES (Dataflow-based detection)
-- ============================================================================

INSERT INTO sast_semgrep_rules (rule_id, name, message, languages, severity, mode, taint_sources, taint_sinks, cwe_ids, owasp_categories, tags, enabled)
VALUES
    (
        'TAINT-SQLI-001',
        'SQL Injection - Taint Flow Analysis',
        'User-controlled data flows to SQL execution without proper parameterization',
        ARRAY['python', 'javascript', 'java', 'csharp'],
        'critical',
        'taint',
        '[
            {"pattern": "request.args"},
            {"pattern": "request.form"},
            {"pattern": "request.GET"},
            {"pattern": "request.POST"},
            {"pattern": "req.query"},
            {"pattern": "req.body"}
        ]'::jsonb,
        '[
            {"pattern": "execute(...)"},
            {"pattern": "executeQuery(...)"},
            {"pattern": "query(...)"},
            {"pattern": "db.query(...)"},
            {"pattern": "cursor.execute(...)"}
        ]'::jsonb,
        ARRAY['CWE-89'],
        ARRAY['A03:2021 - Injection'],
        ARRAY['sql-injection', 'database', 'taint'],
        true
    ),
    (
        'TAINT-CMD-001',
        'Command Injection - Taint Flow Analysis',
        'User input flows to shell command execution without escaping',
        ARRAY['python', 'javascript', 'bash', 'java'],
        'critical',
        'taint',
        '[
            {"pattern": "argv"},
            {"pattern": "sys.argv"},
            {"pattern": "process.argv"},
            {"pattern": "request.args"}
        ]'::jsonb,
        '[
            {"pattern": "os.system(...)"},
            {"pattern": "subprocess.run(...)"},
            {"pattern": "exec(...)"},
            {"pattern": "spawn(...)"},
            {"pattern": "popen(...)"}
        ]'::jsonb,
        ARRAY['CWE-78'],
        ARRAY['A03:2021 - Injection'],
        ARRAY['command-injection', 'shell-exec', 'taint'],
        true
    ),
    (
        'TAINT-XSS-DOM',
        'DOM-based XSS - Taint Flow Analysis',
        'User input from browser APIs flows to DOM without sanitization',
        ARRAY['javascript', 'typescript'],
        'high',
        'taint',
        '[
            {"pattern": "location.href"},
            {"pattern": "location.hash"},
            {"pattern": "location.search"},
            {"pattern": "document.URL"},
            {"pattern": "window.name"}
        ]'::jsonb,
        '[
            {"pattern": "innerHTML"},
            {"pattern": "textContent"},
            {"pattern": "appendChild(...)"},
            {"pattern": "insertAdjacentHTML(...)"}
        ]'::jsonb,
        ARRAY['CWE-79'],
        ARRAY['A03:2021 - Injection'],
        ARRAY['xss', 'dom-xss', 'taint'],
        true
    ),
    (
        'TAINT-PATH-TRAVERSAL',
        'Path Traversal - Taint Flow Analysis',
        'User input flows to file operations without path validation',
        ARRAY['python', 'javascript', 'java', 'php'],
        'high',
        'taint',
        '[
            {"pattern": "request.args"},
            {"pattern": "req.query"},
            {"pattern": "argv"},
            {"pattern": "process.argv"}
        ]'::jsonb,
        '[
            {"pattern": "open(...)"},
            {"pattern": "readFile(...)"},
            {"pattern": "readFileSync(...)"},
            {"pattern": "path.join(...)"},
            {"pattern": "fopen(...)"}
        ]'::jsonb,
        ARRAY['CWE-22'],
        ARRAY['A03:2021 - Injection'],
        ARRAY['path-traversal', 'file-access', 'taint'],
        true
    ),
    (
        'TAINT-LDAPI-CORE',
        'LDAP Injection - Taint Flow Analysis',
        'User input flows to LDAP query without proper encoding',
        ARRAY['java', 'csharp', 'python'],
        'high',
        'taint',
        '[
            {"pattern": "request.args"},
            {"pattern": "getParameter(...)"}
        ]'::jsonb,
        '[
            {"pattern": "search(...)"},
            {"pattern": "createSubcontext(...)"},
            {"pattern": "modifyAttributes(...)"}
        ]'::jsonb,
        ARRAY['CWE-90'],
        ARRAY['A03:2021 - Injection'],
        ARRAY['ldap-injection', 'directory-access', 'taint'],
        true
    ),
    (
        'TAINT-SSTI-001',
        'Server-Side Template Injection - Taint Flow Analysis',
        'User input flows to template rendering without sanitization',
        ARRAY['python', 'javascript', 'java'],
        'high',
        'taint',
        '[
            {"pattern": "request.args.get(...)"},
            {"pattern": "request.form.get(...)"}
        ]'::jsonb,
        '[
            {"pattern": "render_template(...)"},
            {"pattern": "Jinja2(...).render(...)"},
            {"pattern": "ejs.render(...)"}
        ]'::jsonb,
        ARRAY['CWE-1336'],
        ARRAY['A03:2021 - Injection'],
        ARRAY['template-injection', 'ssti', 'taint'],
        true
    ),
    (
        'TAINT-DESER-001',
        'Insecure Deserialization - Taint Flow Analysis',
        'Untrusted data flows to deserialization functions',
        ARRAY['python', 'java', 'javascript'],
        'critical',
        'taint',
        '[
            {"pattern": "request.data"},
            {"pattern": "request.form"},
            {"pattern": "req.body"}
        ]'::jsonb,
        '[
            {"pattern": "pickle.loads(...)"},
            {"pattern": "ObjectInputStream(...)"},
            {"pattern": "JSON.parse(...)"},
            {"pattern": "YAML.load(...)"}
        ]'::jsonb,
        ARRAY['CWE-502'],
        ARRAY['A02:2021 - Cryptographic Failures'],
        ARRAY['deserialization', 'code-execution', 'taint'],
        true
    )
ON CONFLICT (rule_id) DO NOTHING;

-- Log completion and statistics
SELECT
    (SELECT COUNT(*) FROM sast_rules WHERE enabled = true) as total_enabled_sast_rules,
    (SELECT COUNT(*) FROM sast_semgrep_rules WHERE enabled = true) as total_enabled_semgrep_rules;
