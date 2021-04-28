--- Generates MoonSniff traffic, i.e. packets contain an identifier and a fixed bit pattern
--- Live mode and MSCAP mode require this type of traffic

local lm     = require "libmoon"
local device = require "device"
local memory = require "memory"
local ts     = require "timestamping"
local hist   = require "histogram"
local timer  = require "timer"
local log    = require "log"
local stats  = require "stats"
local bit    = require "bit"
local limiter = require "software-ratecontrol"

local MS_TYPE =  0b01010101
local band = bit.band

local SRC_IP	  	= "10.0.0.10"
local DST_IP		= "10.0.250.10"
local SRC_PORT		= 1234
local DST_PORT_BASE	= 1000

function configure(parser)
	parser:description("Generate traffic which can be used by moonsniff to establish latencies induced by a device under test.")
	parser:argument("dev", "Devices to use."):args(2):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):args("*"):default(10000):convert(tonumber)
	parser:option("-v --vlan", "VLANs per Flow"):args("*"):default(-1):convert(tonumber)
	parser:option("-m --mac", "MAC per VLAN"):args("*"):default(-1)
	parser:option("-p --packets", "Send only the number of packets specified"):default(100000):convert(tonumber):target("numberOfPackets")
	parser:option("-x --size", "Packet size in bytes."):convert(tonumber):default(100):target('packetSize')
	parser:option("-b --burst", "Burst in bytes"):args("*"):default(10000):convert(tonumber)
	parser:option("-w --warm-up", "Warm-up device by sending 1000 pkts and pausing n seconds before real test begins."):convert(tonumber):default(0):target('warmUp')
	parser:option("-f --flows", "Number of flows (randomized source IP)."):default(1):convert(tonumber):target('flows')

	return parser:parse()
end

-- Source: https://stackoverflow.com/a/32167188
function shuffle(tbl) -- suffles numeric indices
    local len, random = #tbl, math.random ;
    for i = len, 2, -1 do
        local j = random( 1, i );
        tbl[i], tbl[j] = tbl[j], tbl[i];
    end
    return tbl;
end

local function tableOfFlows(flows, rate)
    local flow_table = {}
	for i=1,flows do
		for x = 1, rate[i]*1000 do
			table.insert(flow_table, i)
		end
	end
	flow_table = shuffle(flow_table)
	return flow_table
end

-- Source: https://stackoverflow.com/questions/8695378/how-to-sum-a-table-of-numbers-in-lua
function sum(t)
    local sum = 0.0
    for k,v in pairs(t) do
        sum = sum + v
    end

    return sum
end

-------------------------------------------------------------------------------
-- Converts a MAC address from its string representation to a numeric one, in
-- network byte order.
-- address  : The address to convert.
-------------------------------------------------------------------------------
function convertMacAddress(address)
	  local bytes = {string.match(address,
                    '(%x+)[-:](%x+)[-:](%x+)[-:](%x+)[-:](%x+)[-:](%x+)')}

    local convertedAddress = 0
    for i = 1, 6 do
        convertedAddress = convertedAddress +
                           tonumber(bytes[i], 16) * 256 ^ (i - 1)
    end
    return convertedAddress
end

function master(args)
	if args.flows ~= (table.getn(args.rate) or table.getn(args.burst) or table.getn(args.vlan)) then
		log:error("Rate and burst are not matching the numbers of flows")
		return -1 -- Error as we have no result here, we need one definition per flow
	end
	args.dev[1] = device.config { port = args.dev[1], txQueues = 1 }
	args.dev[2] = device.config { port = args.dev[2], rxQueues = 1 }
	device.waitForLinks()
	local dev0tx = args.dev[1]:getTxQueue(0)
	local dev1rx = args.dev[2]:getRxQueue(0)

	stats.startStatsTask { txDevices = { args.dev[1] }, rxDevices = { args.dev[2] } }

	dev0tx:setRate(sum(args.rate))
	local flows = tableOfFlows(args.flows, args.rate)

	local sender0 = lm.startTask("generateTraffic", dev0tx, args, flows, args.burst, args.vlan, args.mac)

	if args.warmUp > 0 then
		print('warm up active')
	end

	sender0:wait()
	lm.stop()
	lm.waitForTasks()
end

function generateTraffic(queue, args, flows, burst, vlan, mac)
	local pkt_id = 0
	local mempool = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill {
			pktLength = args.packetSize,
			ethSrc = queue,
			ip4Src = SRC_IP,
			ip4Dst = DST_IP,
			udpSrc = SRC_PORT,
		}
	end)
	local bufs = mempool:bufArray()
	local counter = 0
	local numFlowEntries = table.getn(flows)
	while lm.running() do
		bufs:alloc(args.packetSize)

		for i, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()
			-- for setters to work correctly, the number is not allowed to exceed 16 bit
			pkt.ip4:setID(band(pkt_id, 0xFFFF))
			pkt.payload.uint32[0] = pkt_id
			pkt.payload.uint8[4] = MS_TYPE
			pkt_id = pkt_id + 1
			pkt.udp:setDstPort(DST_PORT_BASE + flows[counter+1])
			pkt.eth:setDst(convertMacAddress(mac[vlan[flows[counter+1]]]))
			buf:setVlan(vlan[flows[counter+1]])
			counter = incAndWrap(counter, numFlowEntries)
		end
		bufs:offloadIPChecksums()
		bufs:offloadUdpChecksums()
		queue:send(bufs)
	end
end
