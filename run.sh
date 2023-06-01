#!/bin/bash

cpu_arch=$(uname -m)
kernel_ver=$(uname -r)

echo "System Information:"
echo "  CPU Architecture : $cpu_arch"
echo "  Kernel Version   : $kernel_ver"
echo

# Extract apps from Makefile
apps=$(grep "^APPS =" Makefile | sed 's/APPS = //' )

# Prepare logs directory
mkdir -p logs

# Arrays to store results
declare -A exit_codes
declare -A test_results

echo "Running tests..."
echo

# Run tests sequentially to capture exit codes
for app in $apps; do
    file="./$app"
    if [[ -x "$file" && -f "$file" ]]; then
        echo -n "  Running $app... "
        if "$file" > "logs/${app}.log" 2>&1; then
            exit_codes["$app"]=0
            echo "✓"
        else
            exit_codes["$app"]=$?
            echo "✗ (exit code: ${exit_codes[$app]})"
        fi
    else
        echo "  $app: NOT FOUND"
        echo "$app : NOT FOUND" > "logs/${app}.log"
        exit_codes["$app"]=-1
    fi
done

echo

echo "╔══════════════════════════════════════════════════════════════════════════════════════╗"
echo "║                             BPF Litmus Test Batch Runner                             ║"
echo "╚══════════════════════════════════════════════════════════════════════════════════════╝"
echo "╔═══════════════════════════════════════╤══════════╤════════════╤════════════╤═════════╗"
echo "║ Test Name                             │ Result   │ Positive   │ Negative   │ Pos %   ║"
echo "╠═══════════════════════════════════════╪══════════╪════════════╪════════════╪═════════╣"

# Analyze logs and display results
for app in $apps; do
    logfile="logs/${app}.log"

    # Determine result based on exit code
    if [[ ${exit_codes[$app]} -eq -1 ]]; then
        result="NOT FOUND"
        result_color=""
    elif [[ ${exit_codes[$app]} -eq 0 ]]; then
        result="✓ OK"
        result_color="\033[32m"  # Green
    else
        result="✗ FAILED"
        result_color="\033[31m"  # Red
    fi

    if [[ ! -f "$logfile" ]] || grep -q "NOT FOUND" "$logfile"; then
        printf "║ %-33s │ %-8s │ %-10s │ %-10s │ %-7s ║\n" "$app" "NOT FOUND" "-" "-" "-"
        continue
    fi

    # Extract values from log
    testname=$(grep -m1 "^  Test:" "$logfile" | awk -F': ' '{print $2}' | head -c 33)
    positive=$(grep -m1 "Positive:" "$logfile" | awk -F'Positive: ' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ')
    negative=$(grep -m1 "Negative:" "$logfile" | awk -F'Negative: ' '{print $2}' | tr -d ' ')

    # Defaults
    if [[ -z "$testname" ]]; then testname="$app"; fi
    if [[ -z "$positive" ]]; then positive=0; fi
    if [[ -z "$negative" ]]; then negative=0; fi

    # Calculate percentage
    total=$((positive + negative))
    if [[ $total -gt 0 ]]; then
        percent=$(awk "BEGIN { printf \"%.2f%%\", ($positive/$total)*100 }")
    else
        percent="0.00%"
    fi

    # Format numbers with commas for readability
    positive_formatted=$(printf "%'d" "$positive" 2>/dev/null || echo "$positive")
    negative_formatted=$(printf "%'d" "$negative" 2>/dev/null || echo "$negative")

    # Print row with color
    printf "║ %-37s │ ${result_color}%-10s\033[0m │ %10s │ %10s │ %7s ║\n" \
           "$testname" "$result" "$positive_formatted" "$negative_formatted" "$percent"
done

echo "╚═══════════════════════════════════════╧══════════╧════════════╧════════════╧═════════╝"

# Summary statistics
total_tests=$(echo $apps | wc -w)
passed_tests=0
failed_tests=0
not_found_tests=0

for app in $apps; do
    case ${exit_codes[$app]} in
        0) ((passed_tests++)) ;;
        -1) ((not_found_tests++)) ;;
        *) ((failed_tests++)) ;;
    esac
done

echo
echo "Summary:"
echo "  Total Tests: $total_tests"
echo "  ✓ Passed:   $passed_tests"
echo "  ✗ Failed:   $failed_tests"
echo "  ⚠ Missing:  $not_found_tests"
echo

if [[ $not_found_tests -gt 0 ]]; then
	echo "⚠ Some test executables are missing. Please run make."
	exit 1
fi

if [[ $failed_tests -gt 0 ]]; then
    echo "⚠ Some tests failed. Check individual logs in the logs/ directory for details."
    exit 1
else
    echo "✓ All available tests completed successfully!"
    exit 0
fi
