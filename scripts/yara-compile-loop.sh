#!/bin/bash
#
# YARA Rule Compile-Review Loop
# Iteratively reviews and fixes YARA rules until they compile successfully
#

set -e

RULE_FILE="$1"
MAX_ITERATIONS=5

if [ -z "$RULE_FILE" ]; then
    echo "Usage: yara-compile-loop.sh <rule-file.yar>"
    exit 1
fi

if [ ! -f "$RULE_FILE" ]; then
    echo "Error: Rule file not found: $RULE_FILE"
    exit 1
fi

iteration=1
while [ $iteration -le $MAX_ITERATIONS ]; do
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ITERATION $iteration/$MAX_ITERATIONS"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    # Try to compile
    compile_output=$(yara -c "$RULE_FILE" /dev/null 2>&1)
    compile_status=$?
    
    if [ $compile_status -eq 0 ]; then
        echo "✅ SUCCESS! Rule compiles without errors."
        echo ""
        echo "Final rule:"
        cat "$RULE_FILE"
        exit 0
    fi
    
    # Compilation failed - extract error
    echo "❌ COMPILATION FAILED"
    echo ""
    echo "Errors:"
    echo "$compile_output"
    echo ""
    
    # Create prompt for LLM
    prompt_file="/tmp/yara_fix_prompt_$iteration.txt"
    cat > "$prompt_file" << EOF
You are a YARA rule expert. Fix the compilation errors in this YARA rule.

COMPILATION ERRORS:
$compile_output

CURRENT RULE:
\`\`\`yara
$(cat "$RULE_FILE")
\`\`\`

TASK:
1. Fix ALL compilation errors
2. Ensure all defined strings are referenced in the condition
3. Keep the rule's detection logic intact
4. Return ONLY the fixed YARA rule, no explanations

FIXED RULE:
EOF

    echo "Sending to LLM for fix..."
    echo ""
    
    # Here you would call your LLM - for now, show the prompt
    echo "Prompt saved to: $prompt_file"
    echo ""
    echo "To use with OpenClaw:"
    echo "  cat $prompt_file | openclaw"
    echo ""
    echo "Or manually fix the errors and save to: $RULE_FILE"
    echo ""
    echo "Press Enter when ready to retry compilation..."
    read
    
    iteration=$((iteration + 1))
done

echo ""
echo "⚠️ Max iterations ($MAX_ITERATIONS) reached without successful compilation."
echo "Manual intervention required."
exit 1
