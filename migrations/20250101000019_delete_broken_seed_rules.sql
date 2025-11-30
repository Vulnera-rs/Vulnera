-- Delete broken seed rules that have overly generic patterns
-- These rules don't match real vulnerabilities and were replaced by improved default rules
DELETE FROM sast_rules WHERE rule_id LIKE 'PY-%' OR rule_id LIKE 'JS-%' OR rule_id LIKE 'JAVA-%' OR rule_id LIKE 'CRED-%' OR rule_id LIKE 'KEY-%' OR rule_id LIKE 'WEAK-%' OR rule_id LIKE 'JWT-%' OR rule_id LIKE 'CRYPTO-%' OR rule_id LIKE 'RNG-%' OR rule_id LIKE 'DESER-%' OR rule_id LIKE 'TLS-%' OR rule_id LIKE 'NOSQL-%' OR rule_id LIKE 'XPATHI-%' OR rule_id LIKE 'PTI-%' OR rule_id LIKE 'LDAPI-%';
