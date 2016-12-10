ARGS="--cpuid 0 string json '{\"run\":\"clear_denials\"}'" make vmcall > /dev/null

echo "----------------------------------------"
echo "run vmcalls"
ARGS="--cpuid 0 string json '{\"set\":\"vpid\", \"enabled\": false}'" make vmcall > /dev/null
ARGS="--cpuid 0 string json '{\"set\":\"vpid\", \"enabled\": true}'" make vmcall > /dev/null
ARGS="--cpuid 0 string json '{\"set\":\"vpid\", \"enabled\": false}'" make vmcall > /dev/null
echo ""

echo "----------------------------------------"
echo "dump policy"
echo ""
ARGS="--cpuid 0 string json '{\"dump\":\"policy\"}'" make vmcall
echo ""

echo "----------------------------------------"
echo "dump denials"
echo ""
ARGS="--cpuid 0 string json '{\"dump\":\"denials\"}'" make vmcall
echo ""

ARGS="--cpuid 0 string json '{\"run\":\"clear_denials\"}'" make vmcall > /dev/null
