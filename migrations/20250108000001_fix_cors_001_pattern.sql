-- Fix CORS-001 false positives by updating the overly broad tree-sitter query
-- The original pattern '(object) @obj' matches ANY object literal, causing
-- false positives on module.exports, function returns, etc.
-- 
-- This migration updates the pattern to only match actual CORS misconfigurations:
-- 1. cors({ origin: "*" }) middleware calls
-- 2. { origin: "*" } configuration objects
-- 3. res.header("Access-Control-Allow-Origin", "*") header setting

UPDATE sast_rules 
SET query = '[
  ; Match: cors({ origin: "*" }) - Express/Koa CORS middleware
  (call_expression
    function: (identifier) @fn
    arguments: (arguments
      (object
        (pair
          key: (property_identifier) @key
          value: (string) @value
        )
      )
    )
    (#eq? @fn "cors")
    (#match? @key "(?i)origin")
    (#eq? @value "\"*\"")
  ) @cors
  
  ; Match: { origin: "*" } in any config object with origin key
  (object
    (pair
      key: (property_identifier) @key
      value: (string) @value
    )
    (#match? @key "(?i)origin")
    (#eq? @value "\"*\"")
  ) @cors
  
  ; Match: res.header("Access-Control-Allow-Origin", "*")
  (call_expression
    function: (member_expression
      property: (property_identifier) @method
    )
    arguments: (arguments
      (string) @header
      (string) @value
    )
    (#match? @method "^(header|setHeader|set)$")
    (#match? @header "(?i)access-control-allow-origin")
    (#eq? @value "\"*\"")
  ) @cors
]',
    description = 'CORS allows all origins (*) without restriction. This can expose sensitive data to malicious websites.'
WHERE rule_id = 'CORS-001';

-- Verify the update
SELECT rule_id, name, query FROM sast_rules WHERE rule_id = 'CORS-001';
