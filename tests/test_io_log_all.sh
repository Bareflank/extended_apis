ARGS="string json '{\"set\":\"blacklist_io_access\", \"ports\": []}'" make vmcall > /dev/null
echo "----------------------------------------"
echo "without hypervisor"
time lspci > /dev/null
echo ""
ARGS="string json '{\"set\":\"whitelist_io_access\", \"ports\": []}'" make vmcall > /dev/null
ARGS="string json '{\"set\":\"log_io_access\", \"enabled\": true}'" make vmcall > /dev/null
echo "----------------------------------------"
echo "with hypervisor"
time lspci > /dev/null
echo ""
echo "----------------------------------------"
echo "io access log"
echo ""
ARGS="string json '{\"get\":\"io_access_log\"}'" make vmcall

