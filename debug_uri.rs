use http::Uri;
use std::str::FromStr;

fn main() {
    let uri1 = Uri::from_str("/api/users?id=1 UNION SELECT * FROM passwords").unwrap();
    let uri2 = Uri::from_str("/api/users?id=1+UNION+SELECT+*+FROM+passwords").unwrap();
    
    println!("URI1 query: {:?}", uri1.query());
    println!("URI1 path: {:?}", uri1.path());
    
    println!("URI2 query: {:?}", uri2.query());
    println!("URI2 path: {:?}", uri2.path());
    
    // Test the regex pattern
    use regex::Regex;
    let pattern = Regex::new(r"(?i)\bunion\s+select\b").unwrap();
    
    if let Some(query1) = uri1.query() {
        println!("URI1 query matches pattern: {}", pattern.is_match(query1));
    }
    if let Some(query2) = uri2.query() {
        println!("URI2 query matches pattern: {}", pattern.is_match(query2));
    }
    
    // Test manual strings
    println!("Manual 'UNION SELECT' matches: {}", pattern.is_match("UNION SELECT"));
    println!("Manual 'id=1 UNION SELECT' matches: {}", pattern.is_match("id=1 UNION SELECT"));
    println!("Manual 'id=1+UNION+SELECT' matches: {}", pattern.is_match("id=1+UNION+SELECT"));
}
