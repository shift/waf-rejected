//! Byte-for-byte port of libinjection's SQLi tokenizer and fingerprint engine.
//!
//! This is a transcription of `libinjection-go` v0.2.2 (`sqli.go`,
//! `sqli_parse.go`, `sqli_token.go`, `sqli_helpers.go`), which Coraza
//! v3.3.3 uses for `@detectSQLi`. Keeping the algorithm identical — including
//! its folding rules, its whitelist heuristics and its quirks — is what gives
//! decision parity; do not "clean up" the control flow.
//!
//! Everything operates on bytes. libinjection is byte oriented and the input
//! may be a lossy-decoded request body, so working on `&[u8]` both matches
//! upstream and removes any chance of a UTF-8 boundary panic. The only
//! allocation-free deviation is that a token value is copied into a 32-byte
//! inline buffer instead of borrowing the input (needed for the `merge` step,
//! which builds a temporary `"A B"` string).
//!
//! Cost: one pass over the input per parse mode (at most four passes), a fixed
//! 8-token vector, no heap traffic.

use super::sqli_data::{FINGERPRINTS, KEYWORDS};

const TOKEN_SIZE: usize = 32;
const MAX_TOKENS: usize = 5;
const TOKEN_VEC: usize = 8;

const FLAG_QUOTE_NONE: u8 = 1;
const FLAG_QUOTE_SINGLE: u8 = 2;
const FLAG_QUOTE_DOUBLE: u8 = 4;
const FLAG_SQL_ANSI: u8 = 8;
const FLAG_SQL_MYSQL: u8 = 16;

const T_NONE: u8 = 0;
const T_KEYWORD: u8 = b'k';
const T_UNION: u8 = b'U';
const T_GROUP: u8 = b'B';
const T_EXPRESSION: u8 = b'E';
const T_SQLTYPE: u8 = b't';
const T_FUNCTION: u8 = b'f';
const T_BAREWORD: u8 = b'n';
const T_NUMBER: u8 = b'1';
const T_VARIABLE: u8 = b'v';
const T_STRING: u8 = b's';
const T_OPERATOR: u8 = b'o';
const T_LOGIC_OPERATOR: u8 = b'&';
const T_COMMENT: u8 = b'c';
const T_COLLATE: u8 = b'A';
const T_LEFT_PAREN: u8 = b'(';
const T_RIGHT_PAREN: u8 = b')';
const T_LEFT_BRACE: u8 = b'{';
const T_RIGHT_BRACE: u8 = b'}';
const T_DOT: u8 = b'.';
const T_COMMA: u8 = b',';
const T_COLON: u8 = b':';
const T_SEMICOLON: u8 = b';';
const T_TSQL: u8 = b'T';
const T_UNKNOWN: u8 = b'?';
const T_EVIL: u8 = b'X';
const T_BACKSLASH: u8 = b'\\';

const BYTE_NULL: u8 = 0;
const BYTE_SINGLE: u8 = b'\'';
const BYTE_DOUBLE: u8 = b'"';
const BYTE_TICK: u8 = b'`';

/// Bytes that end a bare word (`parseWord`). Mirrors the Go accept table.
const WORD_ACCEPT: &[u8] = b" []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r\"\xA0\x00";
/// Bytes that end a variable name (`parseVar`).
const VAR_ACCEPT: &[u8] = b" <>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r'`\"";

const fn accept_table(accept: &[u8]) -> [bool; 256] {
    let mut table = [false; 256];
    let mut i = 0;
    while i < accept.len() {
        table[accept[i] as usize] = true;
        i += 1;
    }
    table
}

static WORD_ACCEPT_TABLE: [bool; 256] = accept_table(WORD_ACCEPT);
static VAR_ACCEPT_TABLE: [bool; 256] = accept_table(VAR_ACCEPT);

#[derive(Clone, Copy)]
struct Token {
    /// Position of the token in the original input.
    pos: usize,
    /// Length of the token, truncated to [`TOKEN_SIZE`] - 1 like upstream.
    len: usize,
    /// Number of leading `@` for variables; unused elsewhere.
    category: u8,
    str_open: u8,
    str_close: u8,
    /// Inline copy of the (truncated) token value.
    val: [u8; TOKEN_SIZE],
}

impl Default for Token {
    fn default() -> Self {
        Self {
            pos: 0,
            len: 0,
            category: T_NONE,
            str_open: BYTE_NULL,
            str_close: BYTE_NULL,
            val: [0; TOKEN_SIZE],
        }
    }
}

impl Token {
    fn assign(&mut self, category: u8, pos: usize, length: usize, value: &[u8]) {
        let last = length.min(TOKEN_SIZE - 1).min(value.len());
        self.category = category;
        self.pos = pos;
        self.len = last;
        self.val[..last].copy_from_slice(&value[..last]);
    }

    fn value(&self) -> &[u8] {
        &self.val[..self.len]
    }
}

fn is_unary_op(token: &Token) -> bool {
    if token.category != T_OPERATOR {
        return false;
    }
    match token.len {
        1 => matches!(token.val[0], b'+' | b'-' | b'!' | b'~'),
        2 => token.val[0] == b'!' && token.val[1] == b'!',
        3 => token.val[..3].eq_ignore_ascii_case(b"NOT"),
        _ => false,
    }
}

fn is_arithmetic_op(token: &Token) -> bool {
    token.category == T_OPERATOR
        && token.len == 1
        && matches!(token.val[0], b'*' | b'/' | b'+' | b'-' | b'%')
}

/// ASCII-case-insensitive keyword lookup against the sorted tables.
///
/// Upstream uppercases with `strings.ToUpper` (Unicode aware). Every table key
/// is ASCII, so an ASCII-only fold is equivalent for any input that can match;
/// non-ASCII code points that Unicode maps onto ASCII letters are the one
/// documented divergence.
fn search_keyword(key: &[u8]) -> u8 {
    let cmp = |candidate: &str| -> core::cmp::Ordering {
        let candidate = candidate.as_bytes();
        let n = candidate.len().min(key.len());
        for i in 0..n {
            let ord = candidate[i].cmp(&key[i].to_ascii_uppercase());
            if ord != core::cmp::Ordering::Equal {
                return ord;
            }
        }
        candidate.len().cmp(&key.len())
    };

    match KEYWORDS.binary_search_by(|(word, _)| cmp(word)) {
        Ok(i) => KEYWORDS[i].1,
        Err(_) => match FINGERPRINTS.binary_search_by(|fp| cmp(fp)) {
            Ok(_) => b'F',
            Err(_) => T_NONE,
        },
    }
}

fn flag2delimiter(flag: u8) -> u8 {
    if flag & FLAG_QUOTE_SINGLE != 0 {
        BYTE_SINGLE
    } else if flag & FLAG_QUOTE_DOUBLE != 0 {
        BYTE_DOUBLE
    } else {
        BYTE_NULL
    }
}

fn is_byte_white(ch: u8) -> bool {
    matches!(ch, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | 0xA0 | 0x00)
}

/// Length of the longest prefix of `s` whose bytes are all in `accept`.
fn str_len_spn(s: &[u8], length: usize, accept: &[u8]) -> usize {
    let mut i = 0;
    while i < length && accept.contains(&s[i]) {
        i += 1;
    }
    i
}

fn str_len_cspn(s: &[u8], length: usize, accept: &[bool; 256]) -> usize {
    let mut i = 0;
    while i < length && !accept[s[i] as usize] {
        i += 1;
    }
    i
}

fn is_backslash_escaped(s: &[u8]) -> bool {
    if !s.contains(&b'\\') {
        return false;
    }
    let mut count = 0;
    for &b in s.iter().rev() {
        if b == b'\\' {
            count += 1;
        } else {
            break;
        }
    }
    count % 2 != 0
}

fn is_double_delimiter_escaped(s: &[u8]) -> bool {
    s.len() >= 2 && s[0] == s[1]
}

fn is_mysql_comment(s: &[u8], pos: usize) -> bool {
    pos + 2 < s.len() && s[pos + 2] == b'!'
}

/// Look forward for doubling of a delimiter (`'foo''bar'`).
fn parse_string_core(
    token: &mut Token,
    s: &[u8],
    length: usize,
    pos: usize,
    offset: usize,
    delimiter: u8,
) -> usize {
    let mut str_start = pos + offset;
    token.str_open = if offset > 0 { delimiter } else { BYTE_NULL };

    loop {
        let index = s[str_start..].iter().position(|&b| b == delimiter);
        match index {
            None => {
                token.assign(
                    T_STRING,
                    pos + offset,
                    length - pos - offset,
                    &s[pos + offset..],
                );
                token.str_close = BYTE_NULL;
                return length;
            }
            Some(index) => {
                let quote = str_start + index;
                // Upstream computes the escaped-prefix as
                // `s[start .. start + Index(s[start..], s[quote..])]`, i.e. the
                // first occurrence of the *remaining suffix*, which is the
                // quote itself unless the tail repeats earlier. Reproduce that
                // exactly; it only costs more when the suffix repeats.
                let start = pos + offset;
                let prefix_end = start + find(&s[start..], &s[quote..]).unwrap_or(0);
                if is_backslash_escaped(&s[start..prefix_end]) {
                    str_start = quote + 1;
                    continue;
                }
                if is_double_delimiter_escaped(&s[quote..]) {
                    str_start = quote + 2;
                    continue;
                }
                token.assign(
                    T_STRING,
                    pos + offset,
                    quote - (pos + offset),
                    &s[pos + offset..],
                );
                token.str_close = delimiter;
                return quote + 1;
            }
        }
    }
}

struct State<'a> {
    input: &'a [u8],
    length: usize,
    flags: u8,
    pos: usize,
    token_vec: [Token; TOKEN_VEC],
    current: usize,
    fingerprint: [u8; MAX_TOKENS],
    fp_len: usize,
    stats_comment_ddx: usize,
    stats_comment_hash: usize,
    stats_tokens: usize,
}

impl<'a> State<'a> {
    fn new(input: &'a [u8], flags: u8) -> Self {
        let flags = if flags == 0 {
            FLAG_QUOTE_NONE | FLAG_SQL_ANSI
        } else {
            flags
        };
        Self {
            input,
            length: input.len(),
            flags,
            pos: 0,
            token_vec: [Token::default(); TOKEN_VEC],
            current: 0,
            fingerprint: [0; MAX_TOKENS],
            fp_len: 0,
            stats_comment_ddx: 0,
            stats_comment_hash: 0,
            stats_tokens: 0,
        }
    }

    fn reset(&mut self, flags: u8) {
        *self = Self::new(self.input, flags);
    }

    // ------------------------------------------------------------------
    // Tokenizers
    // ------------------------------------------------------------------

    fn parse_eol_comment(&mut self) -> usize {
        let index = self.input[self.pos..].iter().position(|&b| b == b'\n');
        let cur = self.current;
        match index {
            None => {
                self.token_vec[cur].assign(
                    T_COMMENT,
                    self.pos,
                    self.length - self.pos,
                    &self.input[self.pos..],
                );
                self.length
            }
            Some(index) => {
                self.token_vec[cur].assign(T_COMMENT, self.pos, index, &self.input[self.pos..]);
                self.pos + index + 1
            }
        }
    }

    fn parse_money(&mut self) -> usize {
        let pos = self.pos;
        let cur = self.current;
        if pos + 1 == self.length {
            self.token_vec[cur].assign(T_BAREWORD, pos, 1, b"$");
            return self.length;
        }

        let length = str_len_spn(
            &self.input[pos + 1..],
            self.length - pos - 1,
            b"0123456789.,",
        );
        match length {
            0 => {
                if self.input[pos + 1] == b'$' {
                    // $$ .. find ending $$
                    let index = find(&self.input[pos + 2..], b"$$");
                    match index {
                        None => {
                            self.token_vec[cur].assign(
                                T_STRING,
                                pos + 2,
                                self.length - (pos + 2),
                                &self.input[pos + 2..],
                            );
                            self.token_vec[cur].str_open = b'$';
                            self.token_vec[cur].str_close = BYTE_NULL;
                            self.length
                        }
                        Some(index) => {
                            self.token_vec[cur].assign(
                                T_STRING,
                                pos + 2,
                                index,
                                &self.input[pos + 2..],
                            );
                            self.token_vec[cur].str_open = b'$';
                            self.token_vec[cur].str_close = b'$';
                            pos + 2 + index + 2
                        }
                    }
                } else {
                    // maybe pgsql "$ quoted strings"
                    let xlen = str_len_spn(
                        &self.input[pos + 1..],
                        self.length - pos - 1,
                        b"abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    );
                    if xlen == 0 {
                        self.token_vec[cur].assign(T_BAREWORD, pos, 1, b"$");
                        return pos + 1;
                    }
                    if pos + xlen + 1 == self.length || self.input[pos + xlen + 1] != b'$' {
                        self.token_vec[cur].assign(T_BAREWORD, pos, 1, b"$");
                        return pos + 1;
                    }
                    let tag = &self.input[pos..pos + xlen + 2];
                    let index = find(&self.input[pos + xlen + 2..], tag);
                    match index {
                        None => {
                            self.token_vec[cur].assign(
                                T_STRING,
                                pos + xlen + 2,
                                self.length - pos - xlen - 2,
                                &self.input[pos + xlen + 2..],
                            );
                            self.token_vec[cur].str_open = b'$';
                            self.token_vec[cur].str_close = BYTE_NULL;
                            self.length
                        }
                        Some(index) => {
                            self.token_vec[cur].assign(
                                T_STRING,
                                pos + xlen + 2,
                                index,
                                &self.input[pos + xlen + 2..],
                            );
                            self.token_vec[cur].str_open = b'$';
                            self.token_vec[cur].str_close = b'$';
                            pos + xlen + 2 + index + xlen + 2
                        }
                    }
                }
            }
            1 if self.input[pos + 1] == b'.' => self.parse_word(),
            _ => {
                self.token_vec[cur].assign(T_NUMBER, pos, length + 1, &self.input[pos..]);
                pos + length + 1
            }
        }
    }

    fn parse_other(&mut self) -> usize {
        let cur = self.current;
        self.token_vec[cur].assign(T_UNKNOWN, self.pos, 1, &self.input[self.pos..]);
        self.pos + 1
    }

    fn parse_white(&mut self) -> usize {
        self.pos + 1
    }

    fn parse_operator1(&mut self) -> usize {
        let cur = self.current;
        self.token_vec[cur].assign(T_OPERATOR, self.pos, 1, &self.input[self.pos..]);
        self.pos + 1
    }

    fn parse_byte(&mut self) -> usize {
        let ch = self.input[self.pos];
        let cur = self.current;
        self.token_vec[cur].assign(ch, self.pos, 1, &self.input[self.pos..]);
        self.pos + 1
    }

    fn parse_hash(&mut self) -> usize {
        self.stats_comment_hash += 1;
        if self.flags & FLAG_SQL_MYSQL != 0 {
            self.stats_comment_hash += 1;
            return self.parse_eol_comment();
        }
        let cur = self.current;
        self.token_vec[cur].assign(T_OPERATOR, self.pos, 1, b"#");
        self.pos + 1
    }

    fn parse_dash(&mut self) -> usize {
        let pos = self.pos;
        if pos + 2 < self.length
            && self.input[pos + 1] == b'-'
            && is_byte_white(self.input[pos + 2])
        {
            self.parse_eol_comment()
        } else if pos + 2 == self.length && self.input[pos + 1] == b'-' {
            self.parse_eol_comment()
        } else if pos + 1 < self.length
            && self.input[pos + 1] == b'-'
            && self.flags & FLAG_SQL_ANSI != 0
        {
            self.stats_comment_ddx += 1;
            self.parse_eol_comment()
        } else {
            let cur = self.current;
            self.token_vec[cur].assign(T_OPERATOR, pos, 1, b"-");
            pos + 1
        }
    }

    fn parse_slash(&mut self) -> usize {
        let pos = self.pos;
        if pos + 1 == self.length || self.input[pos + 1] != b'*' {
            return self.parse_operator1();
        }

        let index = find(&self.input[pos + 2..], b"*/");
        let length = match index {
            None => self.length - pos,
            Some(index) => 2 + index + 2,
        };

        let mut ctype = T_COMMENT;
        if let Some(index) = index {
            // Nested comments make PostgreSQL parsing ambiguous, and MySQL
            // version comments are an automatic ban.
            if find(&self.input[pos + 2..pos + 2 + index + 1], b"/*").is_some()
                || is_mysql_comment(self.input, pos)
            {
                ctype = T_EVIL;
            }
        } else if is_mysql_comment(self.input, pos) {
            ctype = T_EVIL;
        }

        let cur = self.current;
        self.token_vec[cur].assign(ctype, pos, length, &self.input[pos..]);
        pos + length
    }

    fn parse_backslash(&mut self) -> usize {
        let pos = self.pos;
        let cur = self.current;
        if pos + 1 < self.length && self.input[pos + 1] == b'N' {
            self.token_vec[cur].assign(T_NUMBER, pos, 2, &self.input[pos..]);
            return pos + 2;
        }
        self.token_vec[cur].assign(T_BACKSLASH, pos, 1, &self.input[pos..]);
        pos + 1
    }

    fn parse_operator2(&mut self) -> usize {
        let pos = self.pos;
        if pos + 1 >= self.length {
            return self.parse_operator1();
        }
        if pos + 2 < self.length
            && self.input[pos] == b'<'
            && self.input[pos + 1] == b'='
            && self.input[pos + 2] == b'>'
        {
            let cur = self.current;
            self.token_vec[cur].assign(T_OPERATOR, pos, 3, &self.input[pos..]);
            return pos + 3;
        }

        let ch = search_keyword(&self.input[pos..pos + 2]);
        if ch != T_NONE {
            let cur = self.current;
            self.token_vec[cur].assign(ch, pos, 2, &self.input[pos..]);
            return pos + 2;
        }
        if self.input[pos] == b':' {
            let cur = self.current;
            self.token_vec[cur].assign(T_COLON, pos, 1, &self.input[pos..]);
            return pos + 1;
        }
        self.parse_operator1()
    }

    fn parse_string(&mut self) -> usize {
        let cur = self.current;
        let delimiter = self.input[self.pos];
        let (pos, length) = (self.pos, self.length);
        parse_string_core(
            &mut self.token_vec[cur],
            self.input,
            length,
            pos,
            1,
            delimiter,
        )
    }

    fn parse_word(&mut self) -> usize {
        let pos = self.pos;
        let length = str_len_cspn(&self.input[pos..], self.length - pos, &WORD_ACCEPT_TABLE);
        let cur = self.current;
        self.token_vec[cur].assign(T_BAREWORD, pos, length, &self.input[pos..]);

        // Look inside the word for "." and "`": what precedes them may be a
        // keyword (`SELECT.1`, `SELECT \`column\``).
        let mut i = 0;
        while i < self.token_vec[cur].len {
            let delimiter = self.token_vec[cur].val[i];
            if delimiter == b'.' || delimiter == b'`' {
                let prefix = &self.token_vec[cur].val[..i];
                let ch = search_keyword(prefix);
                if ch != T_NONE && ch != T_BAREWORD {
                    self.token_vec[cur] = Token::default();
                    self.token_vec[cur].assign(ch, pos, i, &self.input[pos..]);
                    return pos + i;
                }
            }
            i += 1;
        }

        if length < TOKEN_SIZE {
            let word_len = self.token_vec[cur].len;
            let ch = search_keyword(&self.token_vec[cur].val[..word_len]);
            self.token_vec[cur].category = if ch == T_NONE { T_BAREWORD } else { ch };
        }
        pos + length
    }

    fn parse_var(&mut self) -> usize {
        let mut pos = self.pos + 1;
        let cur = self.current;
        if pos < self.length && self.input[pos] == b'@' {
            pos += 1;
        }

        if pos < self.length {
            if self.input[pos] == BYTE_TICK {
                self.pos = pos;
                pos = self.parse_tick();
                self.token_vec[cur].category = T_VARIABLE;
                return pos;
            } else if self.input[pos] == BYTE_SINGLE || self.input[pos] == BYTE_DOUBLE {
                self.pos = pos;
                pos = self.parse_string();
                self.token_vec[cur].category = T_VARIABLE;
                return pos;
            }
        }

        let length = str_len_cspn(&self.input[pos..], self.length - pos, &VAR_ACCEPT_TABLE);
        if length == 0 {
            self.token_vec[cur].assign(T_VARIABLE, pos, 0, &self.input[pos..]);
            return pos;
        }
        self.token_vec[cur].assign(T_VARIABLE, pos, length, &self.input[pos..]);
        pos + length
    }

    fn parse_number(&mut self) -> usize {
        let pos = self.pos;
        let cur = self.current;

        if self.input[pos] == b'0' && pos + 1 < self.length {
            let digits: &[u8] = match self.input[pos + 1] {
                b'X' | b'x' => b"0123456789ABCDEFabcdef",
                b'B' | b'b' => b"01",
                _ => b"",
            };
            if !digits.is_empty() {
                let length = str_len_spn(&self.input[pos + 2..], self.length - pos - 2, digits);
                if length == 0 {
                    self.token_vec[cur].assign(T_BAREWORD, pos, 2, &self.input[pos..]);
                    return pos + 2;
                }
                self.token_vec[cur].assign(T_NUMBER, pos, 2 + length, &self.input[pos..]);
                return pos + 2 + length;
            }
        }

        let mut pos = self.pos;
        let start = pos;
        while pos < self.length && self.input[pos].is_ascii_digit() {
            pos += 1;
        }

        if pos < self.length && self.input[pos] == b'.' {
            pos += 1;
            while pos < self.length && self.input[pos].is_ascii_digit() {
                pos += 1;
            }
            if pos - start == 1 {
                self.token_vec[cur].assign(T_DOT, start, 1, b".");
                return pos;
            }
        }

        let mut have_e = false;
        let mut have_exp = false;
        if pos < self.length && (self.input[pos] == b'E' || self.input[pos] == b'e') {
            have_e = true;
            pos += 1;
            if pos < self.length && (self.input[pos] == b'+' || self.input[pos] == b'-') {
                pos += 1;
            }
            while pos < self.length && self.input[pos].is_ascii_digit() {
                have_exp = true;
                pos += 1;
            }
        }

        // Oracle's ending float/double suffix.
        if pos < self.length && matches!(self.input[pos], b'd' | b'D' | b'f' | b'F') {
            if pos + 1 == self.length {
                pos += 1;
            } else if is_byte_white(self.input[pos + 1]) || self.input[pos + 1] == b';' {
                pos += 1;
            } else if self.input[pos + 1] == b'u' || self.input[pos + 1] == b'U' {
                // `1fUNION` parses as `1f UNION`.
                pos += 1;
            }
        }

        if have_e && !have_exp {
            self.token_vec[cur].assign(T_BAREWORD, start, pos - start, &self.input[start..]);
        } else {
            self.token_vec[cur].assign(T_NUMBER, start, pos - start, &self.input[start..]);
        }
        pos
    }

    fn parse_tick(&mut self) -> usize {
        let cur = self.current;
        let (pos, length) = (self.pos, self.length);
        let end = parse_string_core(
            &mut self.token_vec[cur],
            self.input,
            length,
            pos,
            1,
            BYTE_TICK,
        );
        let word_len = self.token_vec[cur].len;
        let ch = search_keyword(&self.token_vec[cur].val[..word_len]);
        self.token_vec[cur].category = if ch == T_FUNCTION {
            T_FUNCTION
        } else {
            T_BAREWORD
        };
        end
    }

    fn parse_u_string(&mut self) -> usize {
        let pos = self.pos;
        if pos + 2 < self.length
            && self.input[pos + 1] == b'&'
            && self.input[pos + 2] == BYTE_SINGLE
        {
            self.pos += 2;
            let end = self.parse_string();
            let cur = self.current;
            self.token_vec[cur].str_open = b'u';
            if self.token_vec[cur].str_close == BYTE_SINGLE {
                self.token_vec[cur].str_close = b'u';
            }
            return end;
        }
        self.parse_word()
    }

    fn parse_q_string_core(&mut self, offset: usize) -> usize {
        let pos = self.pos + offset;
        if pos >= self.length
            || (self.input[pos] != b'q' && self.input[pos] != b'Q')
            || pos + 2 >= self.length
            || self.input[pos + 1] != BYTE_SINGLE
        {
            return self.parse_word();
        }

        let mut ch = self.input[pos + 2];
        if ch < 33 {
            return self.parse_word();
        }
        ch = match ch {
            b'(' => b')',
            b'[' => b']',
            b'{' => b'}',
            b'<' => b'>',
            other => other,
        };

        let needle = [ch, BYTE_SINGLE];
        let cur = self.current;
        match find(&self.input[pos + 3..], &needle) {
            None => {
                self.token_vec[cur].assign(
                    T_STRING,
                    pos + 3,
                    self.length - pos - 3,
                    &self.input[pos + 3..],
                );
                self.token_vec[cur].str_open = b'q';
                self.token_vec[cur].str_close = BYTE_NULL;
                self.length
            }
            Some(index) => {
                self.token_vec[cur].assign(T_STRING, pos + 3, index, &self.input[pos + 3..]);
                self.token_vec[cur].str_open = b'q';
                self.token_vec[cur].str_close = b'q';
                pos + 3 + index + 2
            }
        }
    }

    fn parse_q_string(&mut self) -> usize {
        self.parse_q_string_core(0)
    }

    fn parse_nq_string(&mut self) -> usize {
        if self.pos + 2 < self.length && self.input[self.pos + 1] == BYTE_SINGLE {
            return self.parse_e_string();
        }
        self.parse_q_string_core(1)
    }

    fn parse_x_string(&mut self) -> usize {
        let pos = self.pos;
        if pos + 2 >= self.length || self.input[pos + 1] != BYTE_SINGLE {
            return self.parse_word();
        }
        let length = str_len_spn(
            &self.input[pos + 2..],
            self.length - pos - 2,
            b"0123456789abcdefABCDEF",
        );
        if pos + 2 + length >= self.length || self.input[pos + 2 + length] != BYTE_SINGLE {
            return self.parse_word();
        }
        let cur = self.current;
        self.token_vec[cur].assign(T_NUMBER, pos, length + 3, &self.input[pos..]);
        pos + 2 + length + 1
    }

    fn parse_b_string(&mut self) -> usize {
        let pos = self.pos;
        if pos + 2 >= self.length || self.input[pos + 1] != BYTE_SINGLE {
            return self.parse_word();
        }
        let length = str_len_spn(&self.input[pos + 2..], self.length - pos - 2, b"01");
        if pos + 2 + length >= self.length || self.input[pos + 2 + length] != BYTE_SINGLE {
            return self.parse_word();
        }
        let cur = self.current;
        self.token_vec[cur].assign(T_NUMBER, pos, length + 3, &self.input[pos..]);
        pos + 2 + length + 1
    }

    fn parse_e_string(&mut self) -> usize {
        let pos = self.pos;
        if pos + 2 >= self.length || self.input[pos + 1] != BYTE_SINGLE {
            return self.parse_word();
        }
        let cur = self.current;
        parse_string_core(
            &mut self.token_vec[cur],
            self.input,
            self.length,
            pos,
            2,
            BYTE_SINGLE,
        )
    }

    fn parse_b_word(&mut self) -> usize {
        let pos = self.pos;
        let end = self.input[pos..].iter().position(|&b| b == b']');
        let cur = self.current;
        match end {
            None => {
                self.token_vec[cur].assign(T_BAREWORD, pos, self.length - pos, &self.input[pos..]);
                self.length
            }
            Some(end) => {
                self.token_vec[cur].assign(T_BAREWORD, pos, end + 1, &self.input[pos..]);
                pos + end + 1
            }
        }
    }

    fn parse_byte_functions(&mut self, ch: u8) -> usize {
        match ch {
            0..=32 => self.parse_white(),
            b'!' => self.parse_operator2(),
            b'"' => self.parse_string(),
            b'#' => self.parse_hash(),
            b'$' => self.parse_money(),
            b'%' => self.parse_operator1(),
            b'&' => self.parse_operator2(),
            b'\'' => self.parse_string(),
            b'(' | b')' => self.parse_byte(),
            b'*' => self.parse_operator2(),
            b'+' => self.parse_operator1(),
            b',' => self.parse_byte(),
            b'-' => self.parse_dash(),
            b'.' => self.parse_number(),
            b'/' => self.parse_slash(),
            b'0'..=b'9' => self.parse_number(),
            b':' => self.parse_operator2(),
            b';' => self.parse_byte(),
            b'<' | b'=' | b'>' => self.parse_operator2(),
            b'?' => self.parse_other(),
            b'@' => self.parse_var(),
            b'B' | b'b' => self.parse_b_string(),
            b'E' | b'e' => self.parse_e_string(),
            b'N' | b'n' => self.parse_nq_string(),
            b'Q' | b'q' => self.parse_q_string(),
            b'U' | b'u' => self.parse_u_string(),
            b'X' | b'x' => self.parse_x_string(),
            b'[' => self.parse_b_word(),
            b'\\' => self.parse_backslash(),
            b']' => self.parse_other(),
            b'^' => self.parse_operator1(),
            b'`' => self.parse_tick(),
            b'{' => self.parse_byte(),
            b'|' => self.parse_operator2(),
            b'}' => self.parse_byte(),
            b'~' => self.parse_operator1(),
            127 | 160 => self.parse_white(),
            _ => self.parse_word(),
        }
    }

    fn tokenize(&mut self) -> bool {
        if self.length == 0 {
            return false;
        }
        let cur = self.current;
        self.token_vec[cur] = Token::default();

        if self.pos == 0 && (self.flags & (FLAG_QUOTE_SINGLE | FLAG_QUOTE_DOUBLE)) != 0 {
            let delimiter = flag2delimiter(self.flags);
            let (pos, length) = (self.pos, self.length);
            self.pos = parse_string_core(
                &mut self.token_vec[cur],
                self.input,
                length,
                pos,
                0,
                delimiter,
            );
            self.stats_tokens += 1;
            return true;
        }

        while self.pos < self.length {
            let ch = self.input[self.pos];
            self.pos = self.parse_byte_functions(ch);
            if self.token_vec[cur].category != T_NONE {
                self.stats_tokens += 1;
                return true;
            }
        }
        false
    }

    // ------------------------------------------------------------------
    // Folding
    // ------------------------------------------------------------------

    fn merge(&mut self, left: usize) -> bool {
        let a = self.token_vec[left];
        let b = self.token_vec[left + 1];
        if !matches!(
            a.category,
            T_KEYWORD
                | T_BAREWORD
                | T_OPERATOR
                | T_UNION
                | T_FUNCTION
                | T_EXPRESSION
                | T_TSQL
                | T_SQLTYPE
        ) {
            return false;
        }
        if !matches!(
            b.category,
            T_KEYWORD
                | T_BAREWORD
                | T_OPERATOR
                | T_UNION
                | T_FUNCTION
                | T_EXPRESSION
                | T_TSQL
                | T_SQLTYPE
                | T_LOGIC_OPERATOR
        ) {
            return false;
        }
        if a.len + b.len + 1 > TOKEN_SIZE {
            return false;
        }

        let mut tmp = [0u8; TOKEN_SIZE + 1];
        tmp[..a.len].copy_from_slice(&a.val[..a.len]);
        tmp[a.len] = b' ';
        tmp[a.len + 1..a.len + 1 + b.len].copy_from_slice(&b.val[..b.len]);
        let merged_len = a.len + b.len + 1;

        let ch = search_keyword(&tmp[..merged_len]);
        if ch != T_NONE {
            self.token_vec[left].assign(ch, a.pos, merged_len, &tmp[..merged_len]);
            return true;
        }
        false
    }

    /// Parse and fold the input, up to five tokens (the fingerprint length).
    fn fold(&mut self) -> usize {
        let mut pos = 0usize;
        let mut left = 0usize;
        let mut more = true;
        let mut last_comment = Token::default();

        self.current = 0;
        while more {
            more = self.tokenize();
            let token = &self.token_vec[self.current];
            if !(token.category == T_COMMENT
                || token.category == T_LEFT_PAREN
                || token.category == T_SQLTYPE
                || is_unary_op(token))
            {
                break;
            }
        }

        if !more {
            return 0;
        }
        pos += 1;

        loop {
            if pos >= MAX_TOKENS {
                let t = &self.token_vec;
                if (t[0].category == T_NUMBER
                    && (t[1].category == T_OPERATOR || t[1].category == T_COMMA)
                    && t[2].category == T_LEFT_PAREN
                    && t[3].category == T_NUMBER
                    && t[4].category == T_RIGHT_PAREN)
                    || (t[0].category == T_BAREWORD
                        && t[1].category == T_OPERATOR
                        && t[2].category == T_LEFT_PAREN
                        && (t[3].category == T_BAREWORD || t[3].category == T_NUMBER)
                        && t[4].category == T_RIGHT_PAREN)
                    || (t[0].category == T_NUMBER
                        && t[1].category == T_RIGHT_PAREN
                        && t[2].category == T_COMMA
                        && t[3].category == T_LEFT_PAREN
                        && t[4].category == T_NUMBER)
                    || (t[0].category == T_BAREWORD
                        && t[1].category == T_RIGHT_PAREN
                        && t[2].category == T_OPERATOR
                        && t[3].category == T_LEFT_PAREN
                        && t[4].category == T_BAREWORD)
                {
                    if pos > MAX_TOKENS {
                        self.token_vec[1] = self.token_vec[5];
                        pos = 2;
                        left = 0;
                    } else {
                        pos = 1;
                        left = 0;
                    }
                }
            }

            if !more || left >= MAX_TOKENS {
                left = pos;
                break;
            }

            // Get up to two tokens.
            while more && pos <= MAX_TOKENS && pos - left < 2 {
                self.current = pos;
                more = self.tokenize();
                if more {
                    if self.token_vec[self.current].category == T_COMMENT {
                        last_comment = self.token_vec[self.current];
                    } else {
                        last_comment.category = T_NONE;
                        pos += 1;
                    }
                }
            }

            if pos - left < 2 {
                left = pos;
                continue;
            }

            // FOLD: "ss" -> "s"; repeated semicolons; unary operators; ...
            match () {
                _ if self.token_vec[left].category == T_STRING
                    && self.token_vec[left + 1].category == T_STRING =>
                {
                    pos -= 1;
                    continue;
                }
                _ if self.token_vec[left].category == T_SEMICOLON
                    && self.token_vec[left + 1].category == T_SEMICOLON =>
                {
                    pos -= 1;
                    continue;
                }
                _ if (self.token_vec[left].category == T_OPERATOR
                    || self.token_vec[left].category == T_LOGIC_OPERATOR)
                    && (is_unary_op(&self.token_vec[left + 1])
                        || self.token_vec[left + 1].category == T_SQLTYPE) =>
                {
                    pos -= 1;
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_LEFT_PAREN
                    && is_unary_op(&self.token_vec[left + 1]) =>
                {
                    pos -= 1;
                    left = left.saturating_sub(1);
                    continue;
                }
                _ if self.merge(left) => {
                    pos -= 1;
                    left = left.saturating_sub(1);
                    continue;
                }
                _ if self.token_vec[left].category == T_SEMICOLON
                    && self.token_vec[left + 1].category == T_FUNCTION
                    && matches!(self.token_vec[left + 1].val[0], b'I' | b'i')
                    && matches!(self.token_vec[left + 1].val[1], b'F' | b'f') =>
                {
                    // Transact-SQL `IF` after a semicolon is control flow.
                    self.token_vec[left + 1].category = T_TSQL;
                    continue;
                }
                _ if (self.token_vec[left].category == T_BAREWORD
                    || self.token_vec[left].category == T_VARIABLE)
                    && self.token_vec[left + 1].category == T_LEFT_PAREN
                    && is_tsql_or_mysql_variable(self.token_vec[left].value()) =>
                {
                    self.token_vec[left].category = T_FUNCTION;
                    continue;
                }
                _ if self.token_vec[left].category == T_KEYWORD
                    && (self.token_vec[left].value().eq_ignore_ascii_case(b"IN")
                        || self.token_vec[left].value().eq_ignore_ascii_case(b"NOT IN")) =>
                {
                    self.token_vec[left].category =
                        if self.token_vec[left + 1].category == T_LEFT_PAREN {
                            T_OPERATOR
                        } else {
                            T_BAREWORD
                        };
                    continue;
                }
                _ if self.token_vec[left].category == T_OPERATOR
                    && (self.token_vec[left].value().eq_ignore_ascii_case(b"LIKE")
                        || self.token_vec[left]
                            .value()
                            .eq_ignore_ascii_case(b"NOT LIKE")) =>
                {
                    if self.token_vec[left + 1].category == T_LEFT_PAREN {
                        self.token_vec[left].category = T_FUNCTION;
                    }
                }
                _ if self.token_vec[left].category == T_SQLTYPE
                    && matches!(
                        self.token_vec[left + 1].category,
                        T_BAREWORD
                            | T_NUMBER
                            | T_SQLTYPE
                            | T_LEFT_PAREN
                            | T_FUNCTION
                            | T_VARIABLE
                            | T_STRING
                    ) =>
                {
                    self.token_vec[left] = self.token_vec[left + 1];
                    pos -= 1;
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_COLLATE
                    && self.token_vec[left + 1].category == T_BAREWORD =>
                {
                    if self.token_vec[left + 1].value().contains(&b'_') {
                        self.token_vec[left + 1].category = T_SQLTYPE;
                        left = 0;
                    }
                }
                _ if self.token_vec[left].category == T_BACKSLASH => {
                    if is_arithmetic_op(&self.token_vec[left + 1]) {
                        self.token_vec[left].category = T_NUMBER;
                    } else {
                        self.token_vec[left] = self.token_vec[left + 1];
                        pos -= 1;
                    }
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_LEFT_PAREN
                    && self.token_vec[left + 1].category == T_LEFT_PAREN =>
                {
                    pos -= 1;
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_RIGHT_PAREN
                    && self.token_vec[left + 1].category == T_RIGHT_PAREN =>
                {
                    pos -= 1;
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_LEFT_BRACE
                    && self.token_vec[left + 1].category == T_BAREWORD =>
                {
                    // MySQL `{ ``.``.id }` is a magic current-db/table case;
                    // blacklist it rather than model it.
                    if self.token_vec[left + 1].len == 0 {
                        self.token_vec[left + 1].category = T_EVIL;
                        return left + 2;
                    }
                    left = 0;
                    pos -= 2;
                    continue;
                }
                _ if self.token_vec[left + 1].category == T_RIGHT_BRACE => {
                    pos -= 1;
                    left = 0;
                    continue;
                }
                _ => {}
            }

            // Two-token handling is exhausted; get a third token.
            while more && pos <= MAX_TOKENS && pos - left < 3 {
                self.current = pos;
                more = self.tokenize();
                if more {
                    if self.token_vec[self.current].category == T_COMMENT {
                        last_comment = self.token_vec[self.current];
                    } else {
                        last_comment.category = T_NONE;
                        pos += 1;
                    }
                }
            }

            if pos - left < 3 {
                left = pos;
                continue;
            }

            // Three-token folding.
            match () {
                _ if self.token_vec[left].category == T_NUMBER
                    && self.token_vec[left + 1].category == T_OPERATOR
                    && self.token_vec[left + 2].category == T_NUMBER =>
                {
                    pos -= 2;
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_OPERATOR
                    && self.token_vec[left + 1].category != T_LEFT_PAREN
                    && self.token_vec[left + 2].category == T_OPERATOR =>
                {
                    pos -= 2;
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_LOGIC_OPERATOR
                    && self.token_vec[left + 2].category == T_LOGIC_OPERATOR =>
                {
                    pos -= 2;
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_VARIABLE
                    && self.token_vec[left + 1].category == T_OPERATOR
                    && matches!(
                        self.token_vec[left + 2].category,
                        T_VARIABLE | T_NUMBER | T_BAREWORD
                    ) =>
                {
                    pos -= 2;
                    left = 0;
                    continue;
                }
                _ if matches!(self.token_vec[left].category, T_BAREWORD | T_NUMBER)
                    && self.token_vec[left + 1].category == T_OPERATOR
                    && matches!(self.token_vec[left + 2].category, T_NUMBER | T_BAREWORD) =>
                {
                    pos -= 2;
                    left = 0;
                    continue;
                }
                _ if matches!(
                    self.token_vec[left].category,
                    T_BAREWORD | T_NUMBER | T_VARIABLE | T_STRING
                ) && self.token_vec[left + 1].category == T_OPERATOR
                    && self.token_vec[left + 1].value() == b"::"
                    && self.token_vec[left + 2].category == T_SQLTYPE =>
                {
                    pos -= 2;
                    left = 0;
                    continue;
                }
                _ if matches!(
                    self.token_vec[left].category,
                    T_BAREWORD | T_NUMBER | T_STRING | T_VARIABLE
                ) && self.token_vec[left + 1].category == T_COMMA
                    && matches!(
                        self.token_vec[left + 2].category,
                        T_NUMBER | T_BAREWORD | T_STRING | T_VARIABLE
                    ) =>
                {
                    pos -= 2;
                    left = 0;
                    continue;
                }
                _ if matches!(
                    self.token_vec[left].category,
                    T_EXPRESSION | T_GROUP | T_COMMA
                ) && is_unary_op(&self.token_vec[left + 1])
                    && self.token_vec[left + 2].category == T_LEFT_PAREN =>
                {
                    self.token_vec[left + 1] = self.token_vec[left + 2];
                    pos -= 1;
                    left = 0;
                    continue;
                }
                _ if matches!(
                    self.token_vec[left].category,
                    T_KEYWORD | T_EXPRESSION | T_GROUP
                ) && is_unary_op(&self.token_vec[left + 1])
                    && matches!(
                        self.token_vec[left + 2].category,
                        T_NUMBER | T_BAREWORD | T_VARIABLE | T_STRING | T_FUNCTION
                    ) =>
                {
                    self.token_vec[left + 1] = self.token_vec[left + 2];
                    pos -= 1;
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_COMMA
                    && is_unary_op(&self.token_vec[left + 1])
                    && matches!(
                        self.token_vec[left + 2].category,
                        T_NUMBER | T_BAREWORD | T_VARIABLE | T_STRING
                    ) =>
                {
                    self.token_vec[left + 1] = self.token_vec[left + 2];
                    left = 0;
                    pos -= 3;
                    continue;
                }
                _ if self.token_vec[left].category == T_COMMA
                    && is_unary_op(&self.token_vec[left + 1])
                    && self.token_vec[left + 2].category == T_FUNCTION =>
                {
                    self.token_vec[left + 1] = self.token_vec[left + 2];
                    pos -= 1;
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_BAREWORD
                    && self.token_vec[left + 1].category == T_DOT
                    && self.token_vec[left + 2].category == T_BAREWORD =>
                {
                    pos -= 2;
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_EXPRESSION
                    && self.token_vec[left + 1].category == T_DOT
                    && self.token_vec[left + 2].category == T_BAREWORD =>
                {
                    self.token_vec[left + 1] = self.token_vec[left + 2];
                    pos -= 1;
                    left = 0;
                    continue;
                }
                _ if self.token_vec[left].category == T_FUNCTION
                    && self.token_vec[left + 1].category == T_LEFT_PAREN
                    && self.token_vec[left + 2].category != T_RIGHT_PAREN
                    && self.token_vec[left].value().eq_ignore_ascii_case(b"USER") =>
                {
                    // `USER(foo)` is not the zero-argument function.
                    self.token_vec[left].category = T_BAREWORD;
                }
                _ => {}
            }

            // No folding: keep the left-most token and retry.
            left += 1;
        }

        // Re-add a trailing comment if there is room.
        if left < MAX_TOKENS && last_comment.category == T_COMMENT {
            self.token_vec[left] = last_comment;
            left += 1;
        }

        if left > MAX_TOKENS {
            left = MAX_TOKENS;
        }
        left
    }

    // ------------------------------------------------------------------
    // Fingerprint and classification
    // ------------------------------------------------------------------

    fn sqli_fingerprint(&mut self, flags: u8) -> &[u8] {
        self.reset(flags);
        let length = self.fold();

        // Magic PHP backquote comment: an unterminated, empty backticked
        // bare word at the end becomes a comment.
        if length > 2
            && self.token_vec[length - 1].category == T_BAREWORD
            && self.token_vec[length - 1].str_open == BYTE_TICK
            && self.token_vec[length - 1].len == 0
            && self.token_vec[length - 1].str_close == BYTE_NULL
        {
            self.token_vec[length - 1].category = T_COMMENT;
        }

        self.fp_len = 0;
        for i in 0..length {
            let c = self.token_vec[i].category;
            // 'X' means parsing could not be done accurately; blacklist.
            if c == T_EVIL {
                self.fingerprint[0] = T_EVIL;
                self.fp_len = 1;
                self.token_vec[0].category = T_EVIL;
                self.token_vec[0].assign(T_EVIL, 0, 1, b"X");
                return &self.fingerprint[..1];
            }
            self.fingerprint[self.fp_len] = c;
            self.fp_len += 1;
        }
        &self.fingerprint[..self.fp_len]
    }

    fn blacklist(&self) -> bool {
        let length = self.fp_len;
        if length == 0 {
            return false;
        }
        let mut fp = [0u8; MAX_TOKENS + 1];
        fp[0] = b'0';
        for i in 0..length {
            let mut ch = self.fingerprint[i];
            if ch.is_ascii_lowercase() {
                ch -= 0x20;
            }
            fp[i + 1] = ch;
        }
        search_keyword(&fp[..length + 1]) == b'F'
    }

    fn not_whitelist(&self) -> bool {
        let length = self.fp_len;
        if length > 1 && self.fingerprint[length - 1] == T_COMMENT {
            // MS Audit log ignores anything containing `sp_password`.
            if find(self.input, b"sp_password").is_some() {
                return true;
            }
        }

        match length {
            2 => {
                if self.fingerprint[1] == T_UNION {
                    return self.stats_tokens != 2;
                }
                if self.token_vec[1].val[0] == b'#' {
                    return false;
                }
                if self.token_vec[0].category == T_BAREWORD
                    && self.token_vec[1].category == T_COMMENT
                    && self.token_vec[1].val[0] != b'/'
                {
                    return false;
                }
                if self.token_vec[0].category == T_NUMBER
                    && self.token_vec[1].category == T_COMMENT
                    && self.token_vec[1].val[0] != b'/'
                {
                    return true;
                }
                if self.token_vec[0].category == T_NUMBER && self.token_vec[1].category == T_COMMENT
                {
                    if self.stats_tokens > 2 {
                        return true;
                    }
                    let idx = self.token_vec[0].len;
                    let ch = match self.input.get(idx) {
                        Some(&ch) => ch,
                        None => return false,
                    };
                    if ch <= 32 {
                        return true;
                    }
                    if ch == b'/' && self.input.get(idx + 1) == Some(&b'*') {
                        return true;
                    }
                    if ch == b'-' && self.input.get(idx + 1) == Some(&b'-') {
                        return true;
                    }
                    return false;
                }
                if self.token_vec[1].len > 2 && self.token_vec[1].val[0] == b'-' {
                    return false;
                }
            }
            3 => {
                match &self.fingerprint[..3] {
                    b"sos" | b"s&s" => {
                        if self.token_vec[0].str_open == BYTE_NULL
                            && self.token_vec[2].str_close == BYTE_NULL
                            && self.token_vec[0].str_close == self.token_vec[2].str_open
                        {
                            return true;
                        }
                        return false;
                    }
                    b"s&n" | b"n&1" | b"1&1" | b"1&v" | b"1&s" if self.stats_tokens == 3 => {
                        return false;
                    }
                    _ => {}
                }
                if self.token_vec[1].category == T_KEYWORD
                    && (self.token_vec[1].len < 5
                        || !self.token_vec[1].val[..4].eq_ignore_ascii_case(b"INTO"))
                {
                    return false;
                }
            }
            _ => {}
        }

        true
    }

    fn check_fingerprint(&self) -> bool {
        self.blacklist() && self.not_whitelist()
    }

    fn reparse_as_mysql(&self) -> bool {
        self.stats_comment_ddx != 0 || self.stats_comment_hash != 0
    }

    fn check(&mut self) -> bool {
        if self.length == 0 {
            return false;
        }

        // Test the input as-is.
        self.sqli_fingerprint(FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
        if self.check_fingerprint() {
            return true;
        } else if self.reparse_as_mysql() {
            self.sqli_fingerprint(FLAG_QUOTE_NONE | FLAG_SQL_MYSQL);
            if self.check_fingerprint() {
                return true;
            }
        }

        // If the input contains a single quote, pretend it started with one.
        if self.input.contains(&BYTE_SINGLE) {
            self.sqli_fingerprint(FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI);
            if self.check_fingerprint() {
                return true;
            } else if self.reparse_as_mysql() {
                self.sqli_fingerprint(FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL);
                if self.check_fingerprint() {
                    return true;
                }
            }
        }

        // Same for a double quote.
        if self.input.contains(&BYTE_DOUBLE) {
            self.sqli_fingerprint(FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL);
            if self.check_fingerprint() {
                return true;
            }
        }

        false
    }
}

/// Column names that behave as functions in T-SQL/MySQL.
fn is_tsql_or_mysql_variable(word: &[u8]) -> bool {
    const NAMES: [&[u8]; 11] = [
        b"USER_ID",
        b"USER_NAME",
        b"DATABASE",
        b"PASSWORD",
        b"USER",
        b"CURRENT_USER",
        b"CURRENT_DATE",
        b"CURRENT_TIME",
        b"CURRENT_TIMESTAMP",
        b"LOCALTIME",
        b"LOCALTIMESTAMP",
    ];
    NAMES.iter().any(|name| word.eq_ignore_ascii_case(name))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Returns `true` when libinjection classifies `input` as SQL injection.
pub(crate) fn is_sqli(input: &[u8]) -> bool {
    State::new(input, 0).check()
}

/// Returns the libinjection fingerprint when `input` is SQLi, for capture/logs.
pub(crate) fn sqli_fingerprint(input: &[u8]) -> Option<Vec<u8>> {
    let mut state = State::new(input, 0);
    if state.check() {
        Some(state.fingerprint[..state.fp_len].to_vec())
    } else {
        None
    }
}
