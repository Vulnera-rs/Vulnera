//! Test data fixtures for vulnera-sast

/// Sample Python code with security issue
pub fn sample_python_vulnerable() -> &'static str {
    r#"import subprocess
def execute_command(user_input):
    subprocess.call(user_input, shell=True)
"#
}

/// Sample JavaScript code with security issue
pub fn sample_javascript_vulnerable() -> &'static str {
    r#"function queryDatabase(userInput) {
    const query = "SELECT * FROM users WHERE id = " + userInput;
    db.query(query);
}
"#
}

/// Sample safe Python code
pub fn sample_python_safe() -> &'static str {
    r#"import subprocess
def execute_command(command):
    # Safe implementation
    subprocess.call([command], shell=False)
"#
}

