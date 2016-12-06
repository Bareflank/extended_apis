echo "----------------------------------------"
echo "without vpid"
ARGS="--cpuid 0 string json '{\"set\":\"vpid\", \"enabled\": false}'" make vmcall > /dev/null
time lspci > /dev/null
echo ""

echo "----------------------------------------"
echo "with vpid"
ARGS="--cpuid 0 string json '{\"set\":\"vpid\", \"enabled\": true}'" make vmcall > /dev/null
time lspci > /dev/null
echo ""

ARGS="--cpuid 0 string json '{\"set\":\"vpid\", \"enabled\": false}'" make vmcall > /dev/null
