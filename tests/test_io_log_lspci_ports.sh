ARGS="string json '{\"set\":\"blacklist_io_access\", \"ports\": []}'" make vmcall > /dev/null
ARGS="string json '{\"set\":\"log_io_access\", \"enabled\": true}'" make vmcall > /dev/null
ARGS="string json '{\"run\":\"clear_io_access_log\"}'" make vmcall > /dev/null

echo "----------------------------------------"
echo "without hypervisor"
time lspci > /dev/null
echo ""

echo "----------------------------------------"
echo "with hypervisor #1"
ARGS="string json '{\"set\":\"blacklist_io_access\", \"ports_hex\": [\"0xCF8\", \"0xCFC\"]}'" make vmcall > /dev/null
time lspci > /dev/null
echo ""

echo "----------------------------------------"
echo "with hypervisor #2"
ARGS="string json '{\"set\":\"blacklist_io_access\", \"ports\": []}'" make vmcall > /dev/null
ARGS="string json '{\"set\":\"trap_on_io_access\", \"port_hex\": \"0xCF8\"}'" make vmcall > /dev/null
ARGS="string json '{\"set\":\"trap_on_io_access\", \"port_hex\": \"0xCFC\"}'" make vmcall > /dev/null
time lspci > /dev/null
echo ""

echo "----------------------------------------"
echo "with hypervisor #3"
ARGS="string json '{\"set\":\"blacklist_io_access\", \"ports\": []}'" make vmcall > /dev/null
ARGS="string json '{\"set\":\"trap_on_io_access\", \"port\": 3320}'" make vmcall > /dev/null
ARGS="string json '{\"set\":\"trap_on_io_access\", \"port\": 3324}'" make vmcall > /dev/null
time lspci > /dev/null
echo ""

echo "----------------------------------------"
echo "io access log"
echo ""
ARGS="string json '{\"get\":\"io_access_log\"}'" make vmcall

