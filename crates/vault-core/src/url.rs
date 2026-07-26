//! The host a stored URL belongs to — the anti-phishing match key.
//!
//! This is one function because it used to be three, and they disagreed. The
//! desktop bridge, the AutoFill FFI and the duplicate finder each grew their own
//! copy, each was hardened against something the others were not, and every one
//! of them was wrong in a way the other two were not:
//!
//! * the bridge ended the authority at `/` only, so an `@` anywhere in a query
//!   or fragment read as userinfo — a stored `https://bank.example#@evil.com`
//!   keyed the credential to `evil.com`, and autofill then offered it there;
//! * the FFI stripped `www.` before lowercasing, so `WWW.GitHub.com` came out as
//!   `www.github.com`, and lowercased ASCII-only, so `MÜNCHEN.DE` came out as
//!   `mÜnchen.de` — both fail closed, but autofill silently stops matching;
//! * the duplicate finder did not do the browser's backslash normalization, so a
//!   crafted URL grouped under the wrong site.
//!
//! Any of those is a bug. Three copies drifting apart is the bug that produces
//! them, so there is now exactly one, and the comparison lives in its tests.
//!
//! Nothing here parses URLs properly on purpose: a full parser would accept
//! things a browser rejects and vice versa, and what matters is agreeing with
//! **the browser**, because the browser decides which site the user actually
//! visited.

/// Bare host of a URL, normalized for matching and display.
///
/// Scheme, path, query, fragment, userinfo and port are stripped; a leading
/// `www.` and a trailing `.` are removed; the result is lowercased. IPv6
/// literals keep their brackets (`[fd00::a1]`), which is the form a URL
/// authority uses and the form shown in the UI. Returns an empty string when
/// there is no host — callers treat that as "never matches".
///
/// The result is the anti-phishing match key, so it MUST agree with how a
/// browser resolves the host of the same string.
pub fn host_of(url: &str) -> String {
    // Browsers strip ASCII tab/CR/LF from a URL and treat backslashes as
    // forward slashes before parsing. Do the same first, or a stored
    // `https://good.com\@evil.com` — which a browser navigates to good.com —
    // is read here as host `evil.com`.
    let normalized: String = url
        .chars()
        .filter(|&c| c != '\t' && c != '\n' && c != '\r')
        .map(|c| if c == '\\' { '/' } else { c })
        .collect();
    let trimmed = normalized.trim();

    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);

    // The authority ends at the first `/`, `?` or `#`. Splitting on `/` alone
    // leaves a query or fragment attached, and then the `rsplit_once('@')`
    // below reads an `@` inside it as userinfo — handing an attacker the host.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);

    // Userinfo is everything before the LAST `@`, per RFC 3986.
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);

    // Strip the port bracket-aware: an IPv6 literal (`[fd00::a1]:8080`) must not
    // be truncated at the first colon inside the address.
    let host = if host.starts_with('[') {
        match host.find(']') {
            Some(end) => &host[..=end],
            None => host, // malformed literal; keep it, it just won't match
        }
    } else {
        host.split_once(':').map(|(h, _)| h).unwrap_or(host)
    };

    // Lowercase BEFORE stripping `www.`, or an uppercase `WWW.` survives. Full
    // Unicode lowercase so IDN hosts compare equal. A trailing dot is the
    // fully-qualified form: `github.com.` is `github.com`.
    let host = host.trim().trim_end_matches('.').to_lowercase();
    host.strip_prefix("www.").unwrap_or(&host).to_string()
}

#[cfg(test)]
mod tests {
    use super::host_of;

    #[test]
    fn extracts_the_matchable_host() {
        assert_eq!(host_of("https://www.github.com/login"), "github.com");
        assert_eq!(host_of("https://www.github.com/login?x=1"), "github.com");
        assert_eq!(host_of("http://example.com:8080/x"), "example.com");
        assert_eq!(
            host_of("https://user:pass@sub.example.com/y"),
            "sub.example.com"
        );
        assert_eq!(
            host_of("http://user@accounts.google.com:443/"),
            "accounts.google.com"
        );
        assert_eq!(host_of("bareword"), "bareword");
        assert_eq!(host_of(""), "");
        assert_eq!(host_of("https://"), "");
    }

    #[test]
    fn case_and_trailing_dot_normalize() {
        // Lowercasing has to happen before `www.` is stripped, or the uppercase
        // form survives and the host never matches its lowercase twin.
        assert_eq!(host_of("https://WWW.GitHub.com/login"), "github.com");
        assert_eq!(host_of("https://Good.COM./x"), "good.com");
        // Full Unicode lowercase, not ASCII-only, so IDN hosts compare equal.
        assert_eq!(host_of("https://MÜNCHEN.DE"), "münchen.de");
    }

    #[test]
    fn ipv6_literals_keep_their_brackets() {
        // Bracket-aware port stripping: the colons inside the address must
        // survive, and the brackets are the form a URL authority uses.
        assert_eq!(host_of("https://[fd00::a1]/admin"), "[fd00::a1]");
        assert_eq!(host_of("https://[::1]:8080/x"), "[::1]");
        assert_eq!(host_of("https://[fd00::1]:8443/z"), "[fd00::1]");
    }

    /// The regression that motivated merging the three copies. Each case is a
    /// stored URL a browser resolves to `bank.example`; reading any other host
    /// out of one means offering that credential on someone else's site.
    #[test]
    fn an_at_sign_after_the_authority_is_not_userinfo() {
        // A query string containing an email address is entirely ordinary, and
        // the old bridge copy read this as host `gmail.com`.
        assert_eq!(
            host_of("https://bank.example?email=me@gmail.com"),
            "bank.example"
        );
        // A fragment is never sent to the server, so the site cannot strip it.
        assert_eq!(host_of("https://bank.example#@evil.com"), "bank.example");
        assert_eq!(
            host_of("https://bank.example/login?ref=@evil.com"),
            "bank.example"
        );
        // Real userinfo still works — it is before the authority's end.
        assert_eq!(host_of("https://me@bank.example/login"), "bank.example");
    }

    #[test]
    fn matches_browser_normalization() {
        // Backslash is a path separator to a browser, so the host is good.com,
        // NOT evil.com — otherwise a good.com credential could be offered on
        // evil.com.
        assert_eq!(host_of(r"https://good.com\@evil.com"), "good.com");
        assert_eq!(host_of(r"https://good.com\login"), "good.com");
        // Browsers strip ASCII tab/CR/LF anywhere in a URL before parsing.
        assert_eq!(host_of("https://good.com\t/login"), "good.com");
        assert_eq!(host_of("https://good.com\n"), "good.com");
        assert_eq!(host_of("https://good\t.com/"), "good.com");
    }
}
