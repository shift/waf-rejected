;; Self-contained ModSecurity-compatible WASM module
;; Simplified version without complex control flow
(module
  ;; Memory for string operations
  (memory (export "memory") 1)
  
  ;; Global variables for state tracking
  (global $requests_processed (mut i32) (i32.const 0))
  (global $requests_blocked (mut i32) (i32.const 0))
  
  ;; Main evaluation function - entry point called by WAF engine
  ;; Takes request data pointer and length, returns 0 for allow, 1 for block
  (func (export "evaluate_request") (param $request_ptr i32) (param $request_len i32) (result i32)
    ;; Local variables
    (local $result i32)
    
    ;; Increment request counter
    (global.set $requests_processed 
      (i32.add (global.get $requests_processed) (i32.const 1)))
    
    ;; Check for XSS - look for <script pattern
    (local.set $result (call $check_for_pattern (local.get $request_ptr) (local.get $request_len) (i32.const 100) (i32.const 6)))
    (if (local.get $result)
      (then
        (global.set $requests_blocked 
          (i32.add (global.get $requests_blocked) (i32.const 1)))
        (return (i32.const 1)) ;; Block request
      )
    )
    
    ;; Check for SQL injection - look for union select
    (local.set $result (call $check_for_pattern (local.get $request_ptr) (local.get $request_len) (i32.const 200) (i32.const 5)))
    (if (local.get $result)
      (then
        (global.set $requests_blocked 
          (i32.add (global.get $requests_blocked) (i32.const 1)))
        (return (i32.const 1)) ;; Block request
      )
    )
    
    ;; Check for command injection - look for semicolon
    (local.set $result (call $check_for_semicolon (local.get $request_ptr) (local.get $request_len)))
    (if (local.get $result)
      (then
        (global.set $requests_blocked 
          (i32.add (global.get $requests_blocked) (i32.const 1)))
        (return (i32.const 1)) ;; Block request
      )
    )
    
    ;; Allow request if no threats detected
    (return (i32.const 0))
  )
  
  ;; Generic pattern matching function
  (func $check_for_pattern (param $data_ptr i32) (param $data_len i32) (param $pattern_ptr i32) (param $pattern_len i32) (result i32)
    (local $i i32)
    (local $j i32)
    (local $match i32)
    
    ;; Simple Boyer-Moore style search
    (local.set $i (i32.const 0))
    (loop $search_loop
      ;; Check if we've reached the end
      (if (i32.gt_u (local.get $i) (i32.sub (local.get $data_len) (local.get $pattern_len)))
        (then (return (i32.const 0)))
      )
      
      ;; Check for pattern match starting at position i
      (local.set $match (i32.const 1))
      (local.set $j (i32.const 0))
      (loop $match_loop
        (if (i32.ge_u (local.get $j) (local.get $pattern_len))
          (then (br $match_loop))
        )
        
        ;; Compare characters (case insensitive)
        (if (i32.ne 
              (call $to_lower (i32.load8_u (i32.add (local.get $data_ptr) (local.get $i) (local.get $j))))
              (i32.load8_u (i32.add (local.get $pattern_ptr) (local.get $j))))
          (then
            (local.set $match (i32.const 0))
            (br $match_loop)
          )
        )
        
        (local.set $j (i32.add (local.get $j) (i32.const 1)))
        (br $match_loop)
      )
      
      ;; If match found, return 1
      (if (local.get $match)
        (then (return (i32.const 1)))
      )
      
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $search_loop)
    )
    
    (return (i32.const 0))
  )
  
  ;; Check for semicolon (simple command injection detection)
  (func $check_for_semicolon (param $data_ptr i32) (param $data_len i32) (result i32)
    (local $i i32)
    
    (local.set $i (i32.const 0))
    (loop $scan
      (if (i32.ge_u (local.get $i) (local.get $data_len))
        (then (return (i32.const 0)))
      )
      
      (if (i32.eq (i32.load8_u (i32.add (local.get $data_ptr) (local.get $i))) (i32.const 59)) ;; ';'
        (then (return (i32.const 1)))
      )
      
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $scan)
    )
    
    (return (i32.const 0))
  )
  
  ;; Helper: Convert character to lowercase
  (func $to_lower (param $char i32) (result i32)
    (if (i32.and (i32.ge_u (local.get $char) (i32.const 65))  ;; 'A'
                 (i32.le_u (local.get $char) (i32.const 90))) ;; 'Z'
      (then (return (i32.add (local.get $char) (i32.const 32))))
    )
    (return (local.get $char))
  )
  
  ;; Get statistics
  (func (export "get_stats") (param $stats_ptr i32)
    ;; Write stats to memory at stats_ptr
    ;; Format: requests_processed (4 bytes), requests_blocked (4 bytes)
    (i32.store (local.get $stats_ptr) (global.get $requests_processed))
    (i32.store (i32.add (local.get $stats_ptr) (i32.const 4)) (global.get $requests_blocked))
  )
  
  ;; Initialize function called when module loads
  (func (export "init") (result i32)
    ;; Initialize pattern data in memory
    (call $init_pattern_data)
    (return (i32.const 0)) ;; Success
  )
  
  ;; Initialize pattern data in memory
  (func $init_pattern_data
    ;; Store pattern strings at known offsets
    ;; Offset 100: "script" (lowercase)
    (i32.store8 (i32.const 100) (i32.const 115)) ;; 's'
    (i32.store8 (i32.const 101) (i32.const 99))  ;; 'c'
    (i32.store8 (i32.const 102) (i32.const 114)) ;; 'r'
    (i32.store8 (i32.const 103) (i32.const 105)) ;; 'i'
    (i32.store8 (i32.const 104) (i32.const 112)) ;; 'p'
    (i32.store8 (i32.const 105) (i32.const 116)) ;; 't'
    
    ;; Offset 200: "union" (lowercase)
    (i32.store8 (i32.const 200) (i32.const 117)) ;; 'u'
    (i32.store8 (i32.const 201) (i32.const 110)) ;; 'n'
    (i32.store8 (i32.const 202) (i32.const 105)) ;; 'i'
    (i32.store8 (i32.const 203) (i32.const 111)) ;; 'o'
    (i32.store8 (i32.const 204) (i32.const 110)) ;; 'n'
  )
)
