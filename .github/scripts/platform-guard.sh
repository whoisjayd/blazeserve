#!/bin/sh
# Fails when shipped code outside src/platform/ asks which operating system it is built for.
# Test modules may, and so may the display strings of `doctor` and the benchmark report.
set -eu
cd "$(dirname "$0")/../.."
find src -name '*.rs' \
    ! -path 'src/platform/*' ! -path 'src/cli/bench/*' ! -path src/cli/doctor.rs ! -name tests.rs \
    -exec awk '
        FNR == 1 { in_tests = 0; previous = "" }
        previous ~ /^#\[cfg\(.*test/ && /^(pub )?mod / { in_tests = 1 }
        !in_tests && /cfg(!|_attr)?\((.*[( ,])?(windows|unix|target_os|target_family)[ ,=)]|std::os::/ {
            printf "%s:%d: %s\n", FILENAME, FNR, $0
            found = 1
        }
        { previous = $0 }
        END { exit found }
    ' {} +
