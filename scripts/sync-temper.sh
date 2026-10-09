#!/usr/bin/env bash
#
# Vendor temper into crates/temper from its source of truth in CrucibleOS.
#
#   scripts/sync-temper.sh --from /path/to/CrucibleOS   refresh the copy
#   scripts/sync-temper.sh --check                      fail if it has drifted
#
# birdhub vendors temper rather than depending on it by path so the Docker
# build context is this repository alone. The cost of a copy is that it can
# drift, so `--check` exists: it compares hashes of everything tracked and
# exits non-zero on any difference, which is the form CI wants. A vendor check
# that only ran when someone remembered to run it would not be a check.
#
# The copy is verbatim except for Cargo.toml. The vendored tree ships no
# `benches/` and no `examples/`, so the `[[bench]]`/`[[example]]` targets that
# point at them are dropped; and Cargo reads build profiles from the workspace
# root only, so a `[profile.*]` table here would be dead weight that the
# CrucibleOS copy never sees either. `--check` therefore compares the
# *transformed* manifest — it must fail on drift, not on the transformation.

set -euo pipefail

# Hard memory ceiling for this script and everything it runs. It hashes text
# files: nothing here needs more than a few megabytes, and the cost of not
# having a bound is not a failed script — it is the machine. The first version
# of transform_manifest's flush() loop never terminated and grew an awk array
# by one element per iteration; it reached 10.4 GB RSS, filled swap and page
# tables, and the kernel's OOM killer then killed processes across the whole
# desktop session. 512 MB is far above what any step needs, and low enough
# that a future runaway dies here, loudly, instead of machine-wide.
ulimit -v 524288

die() {
	echo "$*" >&2
	exit 2
}

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
VENDOR="$REPO_ROOT/crates/temper"

# Tracked files, relative to the crate root. Anything not listed is
# deliberately not vendored (benches, examples, rustfmt.toml, the GitHub
# and contribution docs). NOTICE is vendored on purpose: temper is
# Apache-2.0, and its NOTICE file carries the attribution notices a
# redistributor must keep readable — this repository is one.
FILES=(
	src
	Cargo.toml
	README.md
	CHANGELOG.md
	PROTOCOL.md
	LICENSE
	NOTICE
)

FROM=""
CHECK=0

usage() {
	cat <<'EOF'
usage: sync-temper.sh [--from PATH] [--check]

  --from PATH   CrucibleOS checkout, or the temper crate inside one.
                Defaults to $CRUCIBLEOS, then to a sibling ../CrucibleOS.
  --check       Report differences and exit 1 instead of writing anything.
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--from)
		FROM="${2:-}"
		[ -n "$FROM" ] || {
			echo "--from needs a path" >&2
			exit 2
		}
		shift 2
		;;
	--check)
		CHECK=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

# Accept either the CrucibleOS root or the crate directory itself: the two are
# easy to confuse and the error message would otherwise be about a missing file
# rather than about which one was wanted.
if [ -z "$FROM" ]; then
	FROM="${CRUCIBLEOS:-$REPO_ROOT/../CrucibleOS}"
fi

if [ -d "$FROM/crucible/runtime/temper" ]; then
	SOURCE="$FROM/crucible/runtime/temper"
elif [ -f "$FROM/Cargo.toml" ] && [ -d "$FROM/src" ]; then
	SOURCE="$FROM"
else
	echo "no temper crate at '$FROM' — pass --from with a CrucibleOS checkout" >&2
	exit 2
fi

SOURCE=$(cd -- "$SOURCE" && pwd)

if [ ! -f "$SOURCE/PROTOCOL.md" ]; then
	echo "'$SOURCE' does not look like the temper crate (no PROTOCOL.md)" >&2
	exit 2
fi

# Print a Cargo.toml with the bench/example targets and the standalone build
# profiles removed.
#
# Comment and blank lines are buffered and only flushed once the section they
# introduce is kept, so a dropped table takes its explanatory comment with it
# rather than leaving a paragraph describing something that is no longer there.
transform_manifest() {
	awk '
		# Print the held lines in order, then stop. The first version read
		# `while (held > 0) { print held_lines[++held_i] }` — which never
		# decremented `held`, so flush() ran forever: each iteration advanced
		# the index, creating a new (empty) array element, and memory grew by
		# one element per iteration. The bound must be the index walking to
		# `held`, never `held` changing inside the loop.
		function flush() {
			for (held_i = 1; held_i <= held; held_i++) {
				print held_lines[held_i]
				delete held_lines[held_i]
			}
			held = 0
		}
		function discard() {
			for (held_i = 1; held_i <= held; held_i++) delete held_lines[held_i]
			held = 0
		}
		function hold(line) { held_lines[++held] = line }
		{
			if ($0 ~ /^[[:space:]]*$/) { hold($0); next }
			if ($0 ~ /^[[:space:]]*#/) { hold($0); next }
			if ($0 ~ /^\[/) {
				keep = ($0 !~ /^\[\[?(bench|example)\]\]/) && ($0 !~ /^\[profile\./)
				if (keep) {
					flush()
					print $0
				} else {
					# The buffered comments introduced this section, so they
					# describe what is being dropped and go with it. The first
					# version flushed the buffer unconditionally, before `keep`
					# was consulted, leaving paragraphs about tables that are
					# no longer there.
					discard()
				}
				next
			}
			if (keep) {
				flush()
				print $0
			} else {
				discard()
			}
		}
		END {
			# Trailing comments at EOF are dropped: nothing follows them.
		}
	' "$1"
}

# every file under a directory, relative to it, or nothing if it is absent.
list_files() {
	local dir=$1
	[ -d "$dir" ] || return 0
	(
		cd "$dir" || exit 1
		find . -type f | sed 's|^\./||'
	)
}

# Hash a tracked file, transforming the manifest first. `shasum`/`sha256sum`
# disagree about which one exists, so pick one and insist on it rather than
# quietly skipping the check on a machine that has the other.
hash_file() {
	local path=$1
	if [ "$(basename "$path")" = "Cargo.toml" ]; then
		transform_manifest "$path" | "$SHA"
	else
		"$SHA" <"$path"
	fi
}

# Write a tracked file into the vendored copy: verbatim, except the manifest,
# which is written transformed — the vendored tree ships no benches/ or
# examples/, so the [[bench]]/[[example]] targets that point at them are
# dropped, and a [profile.*] table in a non-root package would only draw a
# warning. A raw copy here would keep the check green forever (it hashes both
# sides through the same transform) while shipping targets that point at
# directories this repository does not have.
write_file() {
	local src=$1 dst=$2
	if [ "$(basename "$src")" = "Cargo.toml" ]; then
		transform_manifest "$src" >"$dst"
	else
		cp "$src" "$dst"
	fi
}

if command -v sha256sum >/dev/null 2>&1; then
	SHA=sha256sum
elif command -v shasum >/dev/null 2>&1; then
	SHA="shasum -a 256"
else
	echo "need sha256sum or shasum" >&2
	exit 2
fi

# Exercise transform_manifest on a fixture with every shape it must handle:
# comments and blank lines buffered before a kept section, a dropped section,
# and a trailing comment at EOF. The output is compared exactly — the first
# version of flush() passed review, shipped, and looped forever the first time
# anything ran it, because nothing exercised the transformer's *output* until
# a real check did. A vendor checker whose own machinery can hang or lie
# proves nothing, so this runs before either mode trusts a hash.
self_test() {
	local fixture expected actual

	fixture=$(mktemp) || die "self-test: mktemp failed"
	cat >"$fixture" <<'EOF'
# comment before package
[package]
name = "fixture"

# comment before the kept section
[keep]
value = 1

# comment before the dropped section
[profile.release]
opt-level = 3

# comment before the second kept section
[keep2]
value = 2

# trailing comment
EOF

	# Both the dropped section and the comment that introduced it must be
	# gone, and the comment before [keep2] must survive. The trailing comment
	# at EOF goes too: nothing follows it. (The command substitutions strip
	# the final newline on both sides of the comparison.)
	expected='# comment before package
[package]
name = "fixture"

# comment before the kept section
[keep]
value = 1

# comment before the second kept section
[keep2]
value = 2'

	actual=$(transform_manifest "$fixture")
	rm -f "$fixture"

	if [ "$actual" != "$expected" ]; then
		{
			echo "self-test FAILED: transform_manifest output does not match"
			diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") || true
		} >&2
		exit 2
	fi
}

drift=0
copied=0
report() {
	drift=1
	echo "drift: $1"
}

self_test

for entry in "${FILES[@]}"; do
	src="$SOURCE/$entry"
	dst="$VENDOR/$entry"

	if [ ! -e "$src" ]; then
		echo "missing in source: $entry" >&2
		exit 2
	fi

	if [ -d "$src" ]; then
		# Walk the union of both sides, so a file that exists only in the
		# vendored copy is drift too — a vendor check that only looked at the
		# source would not notice a stale file left behind by a rename.
		#
		# Hashes land in variables and are checked before use. Comparing
		# `[ "$(hash_file a)" != "$(hash_file b)" ]` directly looks
		# equivalence-shaped, but a hash that *fails* yields empty output on
		# both sides and reads as equal — a silent skip. Count the result.
		while IFS= read -r rel; do
			[ -n "$rel" ] || continue
			_src_file="$src/$rel"
			_dst_file="$dst/$rel"

			if [ ! -f "$_src_file" ]; then
				if [ "$CHECK" = 1 ]; then
					report "$entry/$rel exists only in the vendored copy"
				else
					echo "removing $entry/$rel (not in source)"
					rm -f "$_dst_file"
					copied=1
				fi
				continue
			fi

			_want=$(hash_file "$_src_file") || die "hashing failed: $_src_file"
			[ -n "$_want" ] || die "empty hash for $_src_file"

			if [ ! -f "$_dst_file" ]; then
				if [ "$CHECK" = 1 ]; then
					report "$entry/$rel is missing from the vendored copy"
				else
					echo "vendoring $entry/$rel"
					mkdir -p "$(dirname "$_dst_file")"
					write_file "$_src_file" "$_dst_file"
					copied=1
				fi
				continue
			fi

			_have=$(hash_file "$_dst_file") || die "hashing failed: $_dst_file"
			[ -n "$_have" ] || die "empty hash for $_dst_file"

			if [ "$_want" != "$_have" ]; then
				if [ "$CHECK" = 1 ]; then
					report "$entry/$rel differs"
				else
					echo "vendoring $entry/$rel"
					write_file "$_src_file" "$_dst_file"
					copied=1
				fi
			fi
		done < <(
			{
				list_files "$src"
				list_files "$dst"
			} | sort -u
		)
		continue
	fi

	if [ ! -f "$dst" ]; then
		if [ "$CHECK" = 1 ]; then
			report "$entry is missing from the vendored copy"
		else
			echo "vendoring $entry"
			write_file "$src" "$dst"
			copied=1
		fi
		continue
	fi

	_want=$(hash_file "$src") || die "hashing failed: $src"
	[ -n "$_want" ] || die "empty hash for $src"
	_have=$(hash_file "$dst") || die "hashing failed: $dst"
	[ -n "$_have" ] || die "empty hash for $dst"

	if [ "$_want" != "$_have" ]; then
		if [ "$CHECK" = 1 ]; then
			report "$entry differs"
		else
			echo "vendoring $entry"
			write_file "$src" "$dst"
			copied=1
		fi
	fi
done

if [ "$CHECK" = 1 ]; then
	if [ "$drift" = 1 ]; then
		echo ""
		echo "crates/temper has drifted from $SOURCE — run scripts/sync-temper.sh" >&2
		exit 1
	fi
	echo "crates/temper matches $SOURCE"
	exit 0
fi

if [ "$copied" = 1 ]; then
	echo "vendored temper refreshed from $SOURCE"
else
	echo "crates/temper already matches $SOURCE"
fi
