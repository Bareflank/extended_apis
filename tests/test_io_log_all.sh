ARGS="--cpuid 0 string json '{\"set\":\"blacklist_io_access\", \"ports\": []}'" make vmcall > /dev/null
ARGS="--cpuid 0 string json '{\"set\":\"log_io_access\", \"enabled\": true}'" make vmcall > /dev/null
ARGS="--cpuid 0 string json '{\"run\":\"clear_io_access_log\"}'" make vmcall > /dev/null

echo "----------------------------------------"
echo "without hypervisor"
time lspci > /dev/null
echo ""

echo "----------------------------------------"
echo "with hypervisor"
ARGS="--cpuid 0 string json '{\"set\":\"whitelist_io_access\", \"ports\": []}'" make vmcall > /dev/null
time lspci > /dev/null
echo ""

echo "----------------------------------------"
echo "io access log"
echo ""
ARGS="--cpuid 0 string json '{\"get\":\"io_access_log\"}'" make vmcall

ARGS="--cpuid 0 string json '{\"set\":\"blacklist_io_access\", \"ports\": []}'" make vmcall > /dev/null
ARGS="--cpuid 0 string json '{\"set\":\"log_io_access\", \"enabled\": false}'" make vmcall > /dev/null
ARGS="--cpuid 0 string json '{\"run\":\"clear_io_access_log\"}'" make vmcall > /dev/null
