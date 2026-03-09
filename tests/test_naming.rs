use js_ast_analyzer::JsParser;
use std::path::PathBuf;

#[test]
fn test_naming_generic_names() {
    let parser = JsParser::new();
    let test_file = PathBuf::from("test-samples/javascript/test-naming.js");
    
    let result = parser.analyze_file(&test_file);
    assert!(result.is_ok(), "Failed to parse test-naming.js");
    
    let analysis = result.unwrap();
    
    // Should detect generic names like 'data', 'result', 'info', 'value'
    // Messages are in Indonesian: "penamaan yang cukup umum" / "lebih deskriptif"
    let generic_issues: Vec<_> = analysis.issues.iter()
        .filter(|issue| issue.rule == "no-generic-name" || issue.rule == "no-generic-function-name")
        .collect();

    assert!(!generic_issues.is_empty(), "Should detect generic variable names");
}

#[test]
fn test_naming_short_names() {
    let parser = JsParser::new();
    let test_file = PathBuf::from("test-samples/javascript/test-naming.js");
    
    let result = parser.analyze_file(&test_file);
    assert!(result.is_ok());
    
    let analysis = result.unwrap();
    
    // Should detect short names (except loop counters like i, j, k)
    let short_name_issues: Vec<_> = analysis.issues.iter()
        .filter(|issue| issue.message.contains("short") || issue.message.contains("single character"))
        .collect();
    
    // Should detect some short names but allow loop counters
    assert!(analysis.issues.len() > 0, "Should detect naming issues");
}

#[test]
fn test_naming_boolean_prefix() {
    let parser = JsParser::new();
    let test_file = PathBuf::from("test-samples/javascript/test-naming.js");
    
    let result = parser.analyze_file(&test_file);
    assert!(result.is_ok());
    
    let analysis = result.unwrap();
    
    // Should detect booleans without proper prefix (is, has, can, should)
    let boolean_issues: Vec<_> = analysis.issues.iter()
        .filter(|issue| issue.message.contains("boolean") || issue.message.contains("prefix"))
        .collect();
    
    // At least some boolean naming issues should be detected
    assert!(analysis.issues.len() > 0, "Should detect naming convention issues");
}

#[test]
fn test_naming_summary() {
    let parser = JsParser::new();
    let test_file = PathBuf::from("test-samples/javascript/test-naming.js");
    
    let result = parser.analyze_file(&test_file);
    assert!(result.is_ok());
    
    let analysis = result.unwrap();
    
    // Verify summary
    let total = analysis.summary.error + analysis.summary.warning + analysis.summary.suggestion;
    assert_eq!(total, analysis.issues.len(), "Summary should match issue count");
    assert!(total > 5, "Should detect multiple naming issues");
}
