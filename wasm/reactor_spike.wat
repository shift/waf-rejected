;; Experimental request-in/decision-out WAF reactor ABI spike.
;;
;; This is deliberately tiny: it proves the host ABI (memory + init/eval/free)
;; without any imports, so it runs in a pure-Rust interpreter.  The two
;; hardcoded checks are only stand-ins for a real Coraza/TinyGo reactor:
;;
;;   * any '<' byte        -> block (XSS stand-in)
;;   * the bytes "union "  -> block (SQLi stand-in)
;;
;; ABI:
;;   memory          exported linear memory, at least 1 page (64 KiB)
;;   init() -> i32   0 on success, non-zero on failure
;;   eval(ptr, len)  0 = allow, 1 = block, negative = ABI/protocol error
;;   free(ptr, len)  no-op in the spike; real reactors may reclaim memory
;;
;; The host places the request payload at a fixed scratch offset (1024).
(module
  (memory (export "memory") 1 1)

  (global $initialized (mut i32) (i32.const 0))

  (func (export "init") (result i32)
    global.get $initialized
    if (result i32)
      i32.const 0
    else
      i32.const 1
      global.set $initialized
      i32.const 0
    end)

  (func (export "free") (param $ptr i32) (param $len i32)
    ;; The spike owns no dynamic allocations; a real reactor would release
    ;; the (ptr, len) region here.
    nop)

  ;; Returns 1 if the bytes at [$ptr, $end) contain the 6-byte needle "union ".
  (func $has_sql_union (param $ptr i32) (param $end i32) (result i32)
    (local $p i32)
    local.get $ptr
    local.set $p
    block $done
      loop $scan
        local.get $p
        i32.const 6
        i32.add
        local.get $end
        i32.gt_u
        br_if $done

        local.get $p
        i32.load8_u
        i32.const 117 ;; 'u'
        i32.eq
        if
          local.get $p
          i32.const 1
          i32.add
          i32.load8_u
          i32.const 110 ;; 'n'
          i32.eq
          if
            local.get $p
            i32.const 2
            i32.add
            i32.load8_u
            i32.const 105 ;; 'i'
            i32.eq
            if
              local.get $p
              i32.const 3
              i32.add
              i32.load8_u
              i32.const 111 ;; 'o'
              i32.eq
              if
                local.get $p
                i32.const 4
                i32.add
                i32.load8_u
                i32.const 110 ;; 'n'
                i32.eq
                if
                  local.get $p
                  i32.const 5
                  i32.add
                  i32.load8_u
                  i32.const 32 ;; ' '
                  i32.eq
                  if
                    i32.const 1
                    return
                  end
                end
              end
            end
          end
        end

        local.get $p
        i32.const 1
        i32.add
        local.set $p
        br $scan
      end
    end
    i32.const 0)

  ;; Returns 1 if the bytes at [$ptr, $end) contain '<'.
  (func $has_xss_marker (param $ptr i32) (param $end i32) (result i32)
    (local $p i32)
    local.get $ptr
    local.set $p
    block $done
      loop $scan
        local.get $p
        local.get $end
        i32.ge_u
        br_if $done
        local.get $p
        i32.load8_u
        i32.const 60 ;; '<'
        i32.eq
        if
          i32.const 1
          return
        end
        local.get $p
        i32.const 1
        i32.add
        local.set $p
        br $scan
      end
    end
    i32.const 0)

  (func (export "eval") (param $ptr i32) (param $len i32) (result i32)
    (local $end i32)

    global.get $initialized
    i32.eqz
    if
      i32.const -1 ;; init() was not called
      return
    end

    local.get $ptr
    i32.const 0
    i32.lt_s
    local.get $len
    i32.const 0
    i32.lt_s
    i32.or
    if
      i32.const -2 ;; negative pointer/length
      return
    end

    ;; ptr + len must not wrap around the 32-bit address space.
    local.get $ptr
    i32.const -1
    local.get $len
    i32.sub
    i32.gt_u
    if
      i32.const -3 ;; pointer/length overflow
      return
    end

    local.get $ptr
    local.get $len
    i32.add
    local.set $end

    local.get $end
    memory.size
    i32.const 65536
    i32.mul
    i32.gt_u
    if
      i32.const -3 ;; out of bounds
      return
    end

    local.get $ptr
    local.get $end
    call $has_xss_marker
    if
      i32.const 1
      return
    end

    local.get $ptr
    local.get $end
    call $has_sql_union
    if
      i32.const 1
      return
    end

    i32.const 0)
)
