#!/usr/bin/env bash
#
# Audit the configuration schema against runtime reads.
#
# Enumerates every key in the serde schema (including `Option::None` fields)
# via the ignored `print_config_key_paths` unit test, then reports keys whose
# name is never referenced in `src/` outside `config.rs`. This is a heuristic
# starting point: a key can be read through a `config.rs` accessor, so review
# the `config.rs` hit before declaring it dead. The regression guard is
# `every_config_key_is_consumed_or_removed`, not this script.
#
# Usage:
#   ./scripts/audit-config-keys.sh
#   CONFIG_AUDIT_NIX=0 ./scripts/audit-config-keys.sh

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${CONFIG_AUDIT_NIX:-1}" == "0" ]]; then
  CARGO_RUNNER=(cargo)
else
  CARGO_RUNNER=(nix develop -c cargo)
fi

KEYS_FILE="$(mktemp)"
trap 'rm -f "$KEYS_FILE"' EXIT

"${CARGO_RUNNER[@]}" test --lib config::tests::print_config_key_paths \
  -- --ignored --nocapture 2>/dev/null \
  | sed -n 's/^KEY //p' >"$KEYS_FILE"

printf 'Declared config keys: %s\n\n' "$(wc -l <"$KEYS_FILE" | tr -d ' ')"
printf '%-64s %s\n' 'KEY' 'SRC HITS (outside config.rs)'
printf '%-64s %s\n' '---' '---------------------------'

perl -e '
use strict;
use warnings;
use File::Find;

my $keys_file = shift @ARGV;
open my $kf, "<", $keys_file or die $!;
my @keys = grep { /\S/ } map { chomp; $_ } <$kf>;

my @files;
find(
    sub {
        push @files, $File::Find::name
          if /\.rs$/
          && $File::Find::name !~ m{src/config\.rs$}
          && $File::Find::name !~ m{/tests?/};
    },
    "src"
);
my %text;
for my $path (@files) {
    open my $fh, "<", $path or next;
    local $/;
    $text{$path} = <$fh>;
}

for my $key (@keys) {
    my @parts = split /\./, $key;
    my $leaf = pop @parts;
    $leaf =~ s/\[\]$//;
    my @hits;
    for my $path (sort keys %text) {
        push @hits, $path if $text{$path} =~ /\b\Q$leaf\E\b/;
    }
    printf "%-64s %s\n", $key, (@hits ? scalar @hits : "NONE");
}
' "$KEYS_FILE"
