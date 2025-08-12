fn main() {
    use regex::Regex;
    
    // Test SQL injection pattern
    let sql_pattern = Regex::new(r"(?i)\bunion(\s|%20|\+)+select\b").unwrap();
    println!("SQL pattern matches 'UNION+SELECT': {}", sql_pattern.is_match("UNION+SELECT"));
    println!("SQL pattern matches 'id=1+UNION+SELECT+*': {}", sql_pattern.is_match("id=1+UNION+SELECT+*"));
    
    // Test XSS pattern  
    let xss_pattern = Regex::new(r"(?i)(<|%3C)script[^>%]*?(>|%3E)").unwrap();
    println!("XSS pattern matches '%3Cscript%3E': {}", xss_pattern.is_match("%3Cscript%3E"));
    println!("XSS pattern matches '<script>': {}", xss_pattern.is_match("<script>"));
    
    // Test command injection pattern
    let cmd_pattern = Regex::new(r"(?i)(;|&&|\|\|)(\s|%20|\+)*(cat|ls|ps|id|whoami|pwd)\b").unwrap();
    println!("Command pattern matches ';cat': {}", cmd_pattern.is_match(";cat"));
    println!("Command pattern matches ';+cat': {}", cmd_pattern.is_match(";+cat"));
    println!("Command pattern matches 'test;cat+/etc/passwd': {}", cmd_pattern.is_match("test;cat+/etc/passwd"));
}
