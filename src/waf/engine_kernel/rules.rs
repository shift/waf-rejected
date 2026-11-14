//! Hand-written rule subset for the engine-kernel prototype.
//!
//! The rules are deliberately a small, auditable slice of OWASP CRS 4.14.0.
//! Regex sources are copied from the vendored bundle so a corpus decision is
//! comparable; targets and transform pipelines are modelled explicitly.
//! Rules that need libinjection (`@detectSQLi`/`@detectXSS`), multipart, XML
//! or base64 decoding are intentionally absent and are reported as uncovered.

use super::matcher::{Guard, MatcherDef, Phase, Predicate, ValuePredicate};
use super::state::TargetMask;
use super::transform::Transform;

/// `scanners-user-agents.data` from the vendored CRS bundle.
pub const SCANNERS_USER_AGENTS: &str =
    include_str!("../../../wasm/coraza_reactor/rules/crs/rules/scanners-user-agents.data");
/// `unix-shell.data` from the vendored CRS bundle.
pub const UNIX_SHELL: &str =
    include_str!("../../../wasm/coraza_reactor/rules/crs/rules/unix-shell.data");
/// `java-classes.data` from the vendored CRS bundle.
pub const JAVA_CLASSES: &str =
    include_str!("../../../wasm/coraza_reactor/rules/crs/rules/java-classes.data");

const CRITICAL: u16 = 5;

/// One rule in the compiled DAG.
#[derive(Debug, Clone, Copy)]
pub struct RuleDef {
    pub id: u32,
    pub phase: Phase,
    pub targets: TargetMask,
    pub pipeline: &'static [Transform],
    pub matcher: MatcherDef,
    pub score: u16,
    pub description: &'static str,
}

/// The rules the kernel implements. Keep this sorted by id so the compiled
/// order is deterministic.
pub static RULES: &[RuleDef] = &[
    RuleDef {
        id: 911100,
        phase: Phase::One,
        targets: TargetMask::METHOD,
        pipeline: &[],
        matcher: MatcherDef::Predicate(Predicate::MethodAllowed(&[
            "GET", "HEAD", "POST", "OPTIONS",
        ])),
        score: CRITICAL,
        description: "Method is not allowed by policy",
    },
    RuleDef {
        id: 913100,
        phase: Phase::One,
        targets: TargetMask::USER_AGENT,
        pipeline: &[],
        matcher: MatcherDef::Lines {
            lines: SCANNERS_USER_AGENTS,
            case_insensitive: true,
        },
        score: CRITICAL,
        description: "User-Agent associated with a security scanner",
    },
    RuleDef {
        id: 920270,
        phase: Phase::Two,
        targets: TargetMask::uri()
            .union(TargetMask::ARG_NAME)
            .union(TargetMask::ARG_VALUE),
        pipeline: &[Transform::UrlDecodeUni],
        matcher: MatcherDef::Predicate(Predicate::Value {
            targets: TargetMask::uri()
                .union(TargetMask::ARG_NAME)
                .union(TargetMask::ARG_VALUE)
                .union(TargetMask::HEADER_NAME)
                .union(TargetMask::HEADER_VALUE),
            predicate: ValuePredicate::ContainsByte(0),
        }),
        score: CRITICAL,
        description: "Null character in request",
    },
    RuleDef {
        id: 920420,
        phase: Phase::One,
        targets: TargetMask::CONTENT_TYPE,
        pipeline: &[],
        matcher: MatcherDef::Predicate(Predicate::ContentTypeAllowed(&[
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/xml",
            "application/xml",
            "application/soap+xml",
            "application/json",
        ])),
        score: CRITICAL,
        description: "Request content type is not allowed by policy",
    },
    RuleDef {
        id: 930100,
        phase: Phase::Two,
        targets: TargetMask::uri()
            .union(TargetMask::ARG_NAME)
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::HEADER_NAME)
            .union(TargetMask::HEADER_VALUE),
        pipeline: &[],
        matcher: MatcherDef::RegexGuarded {
            pattern: r##"(?i)(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[56]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))(?:\.(?:%0[01]|\?)?|\?\.?|%(?:2(?:(?:5(?:2|c0%25a))?e|%45)|c0(?:\.|%[256aef]e)|u(?:(?:ff0|002)e|2024)|%32(?:%(?:%6|4)5|E)|(?:e|f(?:(?:8|c%80)%8)?0%8)0%80%ae)|0x2e){2,3}(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[56]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))"##,
            guard: Guard::ContainsAnyAsciiCaseInsensitive(&[b"..", b"%2e", b"0x2e"]),
        },
        score: CRITICAL,
        description: "Path traversal attack (/../) or (/.../)",
    },
    RuleDef {
        id: 930110,
        phase: Phase::Two,
        targets: TargetMask::uri()
            .union(TargetMask::ARG_NAME)
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::HEADER_NAME)
            .union(TargetMask::HEADER_VALUE),
        // CRS also applies cmdLine here, but that deletes the backslash the
        // rule's `[\\/;]` separator needs. Keeping the decoded value and
        // lowercasing it detects the same payloads plus the backslash forms.
        pipeline: &[
            Transform::Utf8ToUnicode,
            Transform::UrlDecodeUni,
            Transform::RemoveNulls,
            Transform::Lowercase,
        ],
        matcher: MatcherDef::RegexGuarded {
            pattern: r##"(?:(?:^|[\x5c/;])\.{2,3}[\x5c/;]|[\x5c/;]\.{2,3}[\x5c/;])"##,
            guard: Guard::ContainsAny(&[b".."]),
        },
        score: CRITICAL,
        description: "Path traversal attack (/../) or (/.../)",
    },
    RuleDef {
        id: 932140,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE),
        pipeline: &[Transform::CmdLine],
        matcher: MatcherDef::RegexGuarded {
            pattern: r##"\b(?:for(?:/[dflr].*)? %+[^ ]+ in\(.*\)[\s\x0b]?do|if(?:/i)?(?: not)?(?: (?:e(?:xist|rrorlevel)|defined|cmdextversion)\b|[ \(].*(?:\b(?:g(?:eq|tr)|equ|neq|l(?:eq|ss))\b|==)))"##,
            guard: Guard::ContainsAny(&[b"for", b"if"]),
        },
        score: CRITICAL,
        description: "Windows FOR/IF command found",
    },
    RuleDef {
        id: 932160,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE),
        pipeline: &[Transform::CmdLine, Transform::NormalizePath],
        matcher: MatcherDef::Lines {
            lines: UNIX_SHELL,
            case_insensitive: true,
        },
        score: CRITICAL,
        description: "Unix shell code found",
    },
    RuleDef {
        id: 933160,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE)
            .union(TargetMask::PATH)
            .union(TargetMask::FILENAME),
        pipeline: &[],
        matcher: MatcherDef::Regex(
            r##"(?is)\b\(?[\"']*(?:assert(?:_options)?|c(?:hr|reate_function)|e(?:val|x(?:ec|p))|f(?:ile(?:group)?|open)|glob|i(?:mage(?:gif|(?:jpe|pn)g|wbmp|xbm)|s_a)|md5|o(?:pendir|rd)|p(?:assthru|open|prev)|(?:read|tmp)file|un(?:pac|lin)k|s(?:tat|ubstr|ystem))(?:/(?:\*.*\*/|/.*)|#.*|[\s\x0b\"])*[\"']*\)?[\s\x0b]*\([^\)]*\)"##,
        ),
        score: CRITICAL,
        description: "PHP injection: high-risk function call",
    },
    RuleDef {
        id: 933180,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE)
            .union(TargetMask::PATH)
            .union(TargetMask::FILENAME),
        pipeline: &[],
        matcher: MatcherDef::RegexGuarded {
            pattern: r##"\$+(?:[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*|\s*\{.+\})(?:\s|\[.+\]|\{.+\}|/\*.*\*/|//.*|#.*)*\(.*\)"##,
            guard: Guard::ContainsAny(&[b"$"]),
        },
        score: CRITICAL,
        description: "PHP injection: variable function call",
    },
    RuleDef {
        id: 934100,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE)
            .union(TargetMask::PATH)
            .union(TargetMask::FILENAME),
        pipeline: &[
            Transform::UrlDecodeUni,
            Transform::JsDecode,
            Transform::RemoveWhitespace,
            Transform::Base64Decode,
            Transform::UrlDecodeUni,
            Transform::JsDecode,
            Transform::RemoveWhitespace,
        ],
        matcher: MatcherDef::RegexGuarded {
            pattern: r##"_(?:\$\$ND_FUNC\$\$_|_js_function)|(?:\beval|new[\s\x0b]*Function[\s\x0b]*)\(|String\.fromCharCode|function\(\)\{|this\.constructor|module\.exports=|\([\s\x0b]*[^0-9A-Z_a-z]child_process[^0-9A-Z_a-z][\s\x0b]*\)|process(?:\.(?:(?:a(?:ccess|ppendfile|rgv|vailability)|c(?:aveats|h(?:mod|own)|(?:los|opyfil)e|p|reate(?:read|write)stream)|ex(?:ec(?:file)?|ists)|f(?:ch(?:mod|own)|data(?:sync)?|s(?:tat|ync)|utimes)|inodes|l(?:chmod|ink|stat|utimes)|mkd(?:ir|temp)|open(?:dir)?|r(?:e(?:ad(?:dir|file|link|v)?|name)|m)|s(?:pawn(?:file)?|tat|ymlink)|truncate|u(?:n(?:link|watchfile)|times)|w(?:atchfile|rite(?:file|v)?))(?:sync)?(?:\.call)?\(|binding|constructor|env|global|main(?:Module)?|process|require)|\[[\"'`](?:(?:a(?:ccess|ppendfile|rgv|vailability)|c(?:aveats|h(?:mod|own)|(?:los|opyfil)e|p|reate(?:read|write)stream)|ex(?:ec(?:file)?|ists)|f(?:ch(?:mod|own)|data(?:sync)?|s(?:tat|ync)|utimes)|inodes|l(?:chmod|ink|stat|utimes)|mkd(?:ir|temp)|open(?:dir)?|r(?:e(?:ad(?:dir|file|link|v)?|name)|m)|s(?:pawn(?:file)?|tat|ymlink)|truncate|u(?:n(?:link|watchfile)|times)|w(?:atchfile|rite(?:file|v)?))(?:sync)?|binding|constructor|env|global|main(?:Module)?|process|require)[\"'`]\])|(?:binding|constructor|env|global|main(?:Module)?|process|require)\[|console(?:\.(?:debug|error|info|trace|warn)(?:\.call)?\(|\[[\"'`](?:debug|error|info|trace|warn)[\"'`]\])|require(?:\.(?:resolve(?:\.call)?\(|main|extensions|cache)|\[[\"'`](?:(?:resolv|cach)e|main|extensions)[\"'`]\])"##,
            guard: Guard::ContainsAny(&[
                b"_",
                b"eval",
                b"new",
                b"String",
                b"function",
                b"this",
                b"module",
                b"process",
                b"require",
                b"console",
                b"[",
            ]),
        },
        score: CRITICAL,
        description: "Node.js injection attack",
    },
    RuleDef {
        id: 934160,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE)
            .union(TargetMask::PATH)
            .union(TargetMask::FILENAME),
        pipeline: &[
            Transform::UrlDecodeUni,
            Transform::JsDecode,
            Transform::Base64Decode,
            Transform::UrlDecodeUni,
            Transform::JsDecode,
            Transform::ReplaceComments,
        ],
        matcher: MatcherDef::RegexGuarded {
            pattern: r##"while[\s\x0b]*\([\s\x0b\(]*(?:!+[\s\x0b]*(?:false|null|undefined|NaN|[\+\-]?0|\"{2}|'{2}|`{2})|(?:!!)*(?:(?:t(?:rue|his)|[\+\-]?(?:Infinity|[1-9][0-9]*)|new [A-Za-z][0-9A-Z_a-z]*|window|String|(?:Boolea|Functio)n|Object|Array)\b|\{.*\}|\[.*\]|\"[^\"]+\"|'[^']+'|`[^`]+`)).*\)"##,
            guard: Guard::ContainsAny(&[b"while"]),
        },
        score: CRITICAL,
        description: "Node.js DoS attack",
    },
    RuleDef {
        id: 941110,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE)
            .union(TargetMask::USER_AGENT)
            .union(TargetMask::REFERER)
            .union(TargetMask::PATH)
            .union(TargetMask::FILENAME),
        pipeline: &[
            Transform::Utf8ToUnicode,
            Transform::UrlDecodeUni,
            Transform::HtmlEntityDecode,
            Transform::JsDecode,
            Transform::CssDecode,
            Transform::RemoveNulls,
        ],
        matcher: MatcherDef::Regex(r##"(?i)<script[^>]*>[\s\S]*?"##),
        score: CRITICAL,
        description: "XSS: script tag vector",
    },
    RuleDef {
        id: 941130,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE)
            .union(TargetMask::USER_AGENT)
            .union(TargetMask::PATH)
            .union(TargetMask::FILENAME),
        pipeline: &[
            Transform::Utf8ToUnicode,
            Transform::UrlDecodeUni,
            Transform::HtmlEntityDecode,
            Transform::JsDecode,
            Transform::CssDecode,
            Transform::RemoveNulls,
        ],
        matcher: MatcherDef::Regex(
            r##"(?i).(?:\b(?:(?:x(?:link:href|html|mlns)|data:text/html|formaction)\b|pattern[\s\x0b]*=)|(?:!ENTITY[\s\x0b]+(?:%[\s\x0b]+)?[^\s\x0b]+[\s\x0b]+(?:SYSTEM|PUBLIC)|@import|;base64)\b)"##,
        ),
        score: CRITICAL,
        description: "XSS: attribute vector",
    },
    RuleDef {
        id: 942140,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE),
        pipeline: &[Transform::UrlDecodeUni],
        matcher: MatcherDef::Regex(
            r##"(?i)\b(?:d(?:atabas|b_nam)e[^0-9A-Z_a-z]*\(|(?:information_schema|m(?:aster\.\.sysdatabases|s(?:db|ys(?:ac(?:cess(?:objects|storage|xml)|es)|modules2?|(?:object|querie|relationship)s))|ysql\.db)|northwind|pg_(?:catalog|toast)|tempdb)\b|s(?:chema(?:_name\b|[^0-9A-Z_a-z]*\()|(?:qlite_(?:temp_)?master|ys(?:aux|\.database_name))\b))"##,
        ),
        score: CRITICAL,
        description: "SQL injection: common database names",
    },
    RuleDef {
        id: 942190,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE),
        pipeline: &[Transform::UrlDecodeUni, Transform::RemoveCommentsChar],
        matcher: MatcherDef::RegexGuarded {
            pattern: r##"(?i)[\"'`](?:[\s\x0b]*![\s\x0b]*[\"'0-9A-Z_-z]|;?[\s\x0b]*(?:having|select|union\b[\s\x0b]*(?:all|(?:distin|sele)ct))\b[\s\x0b]*[^\s\x0b])|\b(?:(?:(?:c(?:onnection_id|urrent_user)|database|schema|user)[\s\x0b]*?|select.*?[0-9A-Z_a-z]?user)\(|exec(?:ute)?[\s\x0b]+master\.|from[^0-9A-Z_a-z]+information_schema[^0-9A-Z_a-z]|into[\s\x0b\+]+(?:dump|out)file[\s\x0b]*?[\"'`]|union(?:[\s\x0b]select[\s\x0b]@|[\s\x0b\(0-9A-Z_a-z]*?select))|[\s\x0b]*?exec(?:ute)?.*?[^0-9A-Z_a-z]xp_cmdshell|[^0-9A-Z_a-z]iif[\s\x0b]*?\("##,
            guard: Guard::ContainsAnyAsciiCaseInsensitive(&[
                b"'",
                b"\"",
                b"`",
                b"union",
                b"select",
                b"exec",
                b"from",
                b"into",
                b"iif",
                b"having",
                b"database",
                b"schema",
                b"user",
            ]),
        },
        score: CRITICAL,
        description: "MSSQL code execution and information gathering",
    },
    RuleDef {
        id: 942360,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE),
        pipeline: &[Transform::UrlDecodeUni],
        matcher: MatcherDef::Regex(
            r##"(?i)\b(?:(?:alter|(?:(?:cre|trunc|upd)at|renam)e|de(?:lete|sc)|(?:inser|selec)t|load)[\s\x0b]+(?:char|group_concat|load_file)\b[\s\x0b]*\(?|end[\s\x0b]*?\);)|[\s\x0b\(]load_file[\s\x0b]*?\(|[\"'`][\s\x0b]+regexp[^0-9A-Z_a-z]|[\"'0-9A-Z_-z][\s\x0b]+as\b[\s\x0b]*[\"'0-9A-Z_-z]+[\s\x0b]*\bfrom|^[^A-Z_a-z]+[\s\x0b]*?(?:(?:(?:(?:cre|trunc)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)[\s\x0b]+[0-9A-Z_a-z]+|u(?:pdate[\s\x0b]+[0-9A-Z_a-z]+|nion[\s\x0b]*(?:all|(?:sele|distin)ct)\b)|alter[\s\x0b]*(?:a(?:(?:ggregat|pplication[\s\x0b]*rol)e|s(?:sembl|ymmetric[\s\x0b]*ke)y|u(?:dit|thorization)|vailability[\s\x0b]*group)|b(?:roker[\s\x0b]*priority|ufferpool)|c(?:ertificate|luster|o(?:l(?:latio|um)|nversio)n|r(?:edential|yptographic[\s\x0b]*provider))|d(?:atabase|efault|i(?:mension|skgroup)|omain)|e(?:(?:ndpoi|ve)nt|xte(?:nsion|rnal))|f(?:lashback|oreign|u(?:lltext|nction))|hi(?:erarchy|stogram)|group|in(?:dex(?:type)?|memory|stance)|java|l(?:a(?:ngua|r)ge|ibrary|o(?:ckdown|g(?:file[\s\x0b]*group|in)))|m(?:a(?:s(?:k|ter[\s\x0b]*key)|terialized)|e(?:ssage[\s\x0b]*type|thod)|odule)|(?:nicknam|queu)e|o(?:perator|utline)|p(?:a(?:ckage|rtition)|ermission|ro(?:cedur|fil)e)|r(?:e(?:mot|sourc)e|o(?:l(?:e|lback)|ute))|s(?:chema|e(?:arch|curity|rv(?:er|ice)|quence|ssion)|y(?:mmetric[\s\x0b]*key|nonym)|togroup)|t(?:able(?:space)?|ext|hreshold|r(?:igger|usted)|ype)|us(?:age|er)|view|w(?:ork(?:load)?|rapper)|x(?:ml[\s\x0b]*schema|srobject))\b)"##,
        ),
        score: CRITICAL,
        description: "Concatenated SQL injection and SQLLFI",
    },
    RuleDef {
        id: 942550,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE)
            .union(TargetMask::FILENAME),
        pipeline: &[
            Transform::UrlDecodeUni,
            Transform::Lowercase,
            Transform::RemoveWhitespace,
        ],
        matcher: MatcherDef::RegexGuarded {
            pattern: r##"[\"'`][\[\{].*[\]\}][\"'`].*(::.*jsonb?)?.*(?:(?:@|->?)>|<@|\?[&\|]?|#>>?|[<>]|<-)|(?:(?:@|->?)>|<@|\?[&\|]?|#>>?|[<>]|<-)[\"'`][\[\{].*[\]\}][\"'`]|json_extract.*\(.*\)"##,
            guard: Guard::ContainsAny(&[b"[", b"{", b"json_extract"]),
        },
        score: CRITICAL,
        description: "JSON-based SQL injection",
    },
    RuleDef {
        id: 944100,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE)
            .union(TargetMask::BODY)
            .union(TargetMask::HEADER_NAME)
            .union(TargetMask::HEADER_VALUE),
        pipeline: &[Transform::Lowercase],
        matcher: MatcherDef::Regex(r##"java\.lang\.(?:runtime|processbuilder)"##),
        score: CRITICAL,
        description: "Suspicious Java class detected",
    },
    RuleDef {
        id: 944120,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE)
            .union(TargetMask::BODY)
            .union(TargetMask::HEADER_NAME)
            .union(TargetMask::HEADER_VALUE),
        pipeline: &[Transform::Lowercase],
        matcher: MatcherDef::RegexConjunction {
            first: r##"(?:clonetransformer|forclosure|instantiatefactory|instantiatetransformer|invokertransformer|prototypeclonefactory|prototypeserializationfactory|whileclosure|getproperty|filewriter|xmldecoder)"##,
            second: r##"(?:runtime|processbuilder)"##,
        },
        score: CRITICAL,
        description: "Java serialization RCE",
    },
    RuleDef {
        id: 944130,
        phase: Phase::Two,
        targets: TargetMask::ARG_NAME
            .union(TargetMask::ARG_VALUE)
            .union(TargetMask::COOKIE_NAME)
            .union(TargetMask::COOKIE_VALUE)
            .union(TargetMask::PATH)
            .union(TargetMask::FILENAME)
            .union(TargetMask::BODY)
            .union(TargetMask::HEADER_NAME)
            .union(TargetMask::HEADER_VALUE),
        pipeline: &[],
        matcher: MatcherDef::Lines {
            lines: JAVA_CLASSES,
            case_insensitive: true,
        },
        score: CRITICAL,
        description: "Suspicious Java class",
    },
];

/// Rule ids implemented by this kernel. Used by the corpus coverage report.
pub fn implemented_rule_ids() -> Vec<u32> {
    RULES.iter().map(|rule| rule.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(id: u32) -> &'static str {
        RULES
            .iter()
            .find(|rule| rule.id == id)
            .and_then(|rule| match rule.matcher {
                MatcherDef::Regex(pattern) | MatcherDef::RegexGuarded { pattern, .. } => {
                    Some(pattern)
                }
                _ => None,
            })
            .expect("regex rule")
    }

    #[test]
    fn php_comment_payload_matches() {
        let regex = regex::bytes::Regex::new(pattern(933160)).expect("regex");
        assert!(regex.is_match(b"exec\t/*foo\r\nbar*/\t ()"));
    }

    #[test]
    fn node_new_function_matches_without_whitespace_removal() {
        let regex = regex::bytes::Regex::new(pattern(934100)).expect("regex");
        assert!(regex.is_match(b"new Function ("));
    }

    #[test]
    fn node_while_negation_matches() {
        let regex = regex::bytes::Regex::new(pattern(934160)).expect("regex");
        assert!(regex.is_match(b"while(!+0);"));
    }
}
