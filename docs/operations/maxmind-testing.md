# MaxMind GeoIP Testing

WAF-Rejected can use MaxMind GeoLite2 or GeoIP2 databases for geographic
blocking and Tor/VPN/datacenter detection. The database files are not part of
this repository and must not be committed.

## Licensing

- **GeoLite2** databases are free but require a MaxMind account. They are
  distributed under the
  [GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula)
  and the data is licensed under
  [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
- **GeoIP2** databases require a commercial MaxMind licence and are governed by
  the [GeoIP2 End User License Agreement](https://www.maxmind.com/en/geoip2/eula).
- If you redistribute GeoLite2 data, keep the required attribution:
  "This product includes GeoLite2 data created by MaxMind, available from
  https://www.maxmind.com."

Review the current licence terms before downloading or deploying a database.
Database updates are published by MaxMind on a regular schedule; keep local
copies current.

## Where to Place Databases

Store databases outside the repository, for example:

```text
~/.local/share/waf-rejected/maxmind/GeoLite2-City.mmdb
~/.local/share/waf-rejected/maxmind/GeoIP2-Anonymous-IP.mmdb
```

or, for a system deployment:

```text
/var/lib/waf-rejected/maxmind/GeoLite2-City.mmdb
/var/lib/waf-rejected/maxmind/GeoIP2-Anonymous-IP.mmdb
```

Point the runtime configuration at the absolute paths:

```toml
[waf.geo_blocking]
enabled = true
database_path = "/var/lib/waf-rejected/maxmind/GeoLite2-City.mmdb"
anonymous_database_path = "/var/lib/waf-rejected/maxmind/GeoIP2-Anonymous-IP.mmdb"
```

`anonymous_database_path` is optional. Without it, Tor/VPN/datacenter flags
remain `false`.

## Test Environment Variables

The integration tests are environment-gated so CI never needs licensed data:

| Variable | Database | Required |
| --- | --- | --- |
| `MAXMIND_CITY_DB` | GeoLite2/GeoIP2 City `.mmdb` | For city lookup tests |
| `MAXMIND_ANONYMOUS_DB` | GeoIP2 Anonymous IP `.mmdb` | For anonymous-flag tests |

When a variable is unset or empty, the corresponding test prints a skip message
and passes. When `MAXMIND_ANONYMOUS_DB` is set without `MAXMIND_CITY_DB`, the
anonymous test loads only the anonymous database; an address that is not in
that database is still a successful no-panic lookup.

## Running the Tests

From the repository root, inside the Nix development shell:

```bash
MAXMIND_CITY_DB="$HOME/.local/share/waf-rejected/maxmind/GeoLite2-City.mmdb" \
MAXMIND_ANONYMOUS_DB="$HOME/.local/share/waf-rejected/maxmind/GeoIP2-Anonymous-IP.mmdb" \
nix develop -c cargo test --test integration maxmind
```

To run only the city-backed test:

```bash
MAXMIND_CITY_DB=/path/to/GeoLite2-City.mmdb \
nix develop -c cargo test --test integration city_database
```

The city test resolves `1.1.1.1`, asserts a non-empty country code and checks
that anonymous flags are `false` when no anonymous database is loaded. The
anonymous test loads `MAXMIND_ANONYMOUS_DB` (with the city database when
available) and asserts that the Tor/VPN/datacenter flags are readable booleans
without panicking.

## Handling Test Failures

- `MAXMIND_CITY_DB must point to a readable MaxMind city database`: check the
  path, file permissions and that the file is a valid `.mmdb`.
- `known public IP should resolve from the MaxMind city database`: the database
  may be truncated or from an unexpected edition.
- Empty country code: use a City database, not a Country-only or ASN database.
- Anonymous flags never become `true`: confirm `MAXMIND_ANONYMOUS_DB` points to
  the GeoIP2 Anonymous IP edition and that the tested address is present in the
  local copy.

Never add `.mmdb` files, download URLs containing licence keys, or MaxMind
account credentials to the repository.
