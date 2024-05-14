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

local MS_TYPE = 0b01010101
local band = bit.band

local SRC_IP_BASE	= "198.18.0.0" -- actual address will be SRC_IP_BASE + random(0, flows)

function configure(parser)
	parser:description("Generate traffic which can be used by moonsniff to establish latencies induced by a device under test.")
	parser:argument("dev", "Devices to use."):args(2):convert(tonumber)
	parser:option("-v --fix-packetrate", "Approximate send rate in pps."):convert(tonumber):default(10000):target('fixedPacketRate')
	parser:option("-s --src-mac", "Overwrite source MAC address of every sent packet"):default(''):target("srcMAC")
	parser:option("-d --dst-mac", "Overwrite destination MAC address of every sent packet"):default(''):target("dstMAC")
	parser:option("-l --l4-dst", "Set the layer 4 destination port"):default(23432):target("l4dst")
	parser:option("-p --packets", "Send only the number of packets specified"):default(100000):convert(tonumber):target("numberOfPackets")
	parser:option("-x --size", "Packet size in bytes."):convert(tonumber):default(100):target('packetSize')
	parser:option("-b --burst", "Generated traffic is generated with the specified burst size (default burst size 1)"):default(1):target("burstSize")
	parser:option("-w --warm-up", "Warm-up device by sending 1000 pkts and pausing n seconds before real test begins."):convert(tonumber):default(0):target('warmUp')
        parser:option("-f --flows", "Number of flows (randomized source IP)."):default(1):convert(tonumber):target('flows')

	return parser:parse()
end

function master(args)
	args.dev[1] = device.config { port = args.dev[1], txQueues = 1 }
	args.dev[2] = device.config { port = args.dev[2], rxQueues = 1 }
	device.waitForLinks()
	local dev0tx = args.dev[1]:getTxQueue(0)
	local dev1rx = args.dev[2]:getRxQueue(0)

	stats.startStatsTask { txDevices = { args.dev[1] }, rxDevices = { args.dev[2] } }

        dstmc = parseMacAddress(args.dstMAC, 0)
	srcmc = parseMacAddress(args.srcMAC, 0)


	rateLimiter = limiter:new(dev0tx, "custom")
	local sender0 = lm.startTask("generateTraffic", dev0tx, args, rateLimiter, dstmc, srcmc)

	if args.warmUp > 0 then
		print('warm up active')
	end

	sender0:wait()
	lm.stop()
	lm.waitForTasks()
end

function generateTraffic(queue, args, rateLimiter, dstMAC, srcMAC)
	log:info("Trying to enable rx timestamping of all packets, this isn't supported by most nics")
	local pkt_id = 0
	local baseIP = parseIPAddress(SRC_IP_BASE)
	local numberOfPackets = args.numberOfPackets
	if args.warmUp then
		numberOfPackets = numberOfPackets + 945
	end
	local runtime = timer:new(args.time)
	local mempool = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill {
			pktLength = args.packetSize,
			udpDst = args.l4dst
		}
	end)
	local bufs = mempool:bufArray()
	counter = 0
	delay = 0
	while lm.running() do
		bufs:alloc(args.packetSize)

		for i, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()
			if dstMAC ~= nil then
				pkt.eth:setDst(dstMAC)
			end
			if srcMAC ~= nil then
				pkt.eth:setSrc(srcMAC)
			end

			-- for setters to work correctly, the number is not allowed to exceed 16 bit
			pkt.ip4:setID(band(pkt_id, 0xFFFF))
			pkt.payload.uint32[0] = pkt_id
			pkt.payload.uint8[4] = MS_TYPE
			pkt_id = pkt_id + 1
			numberOfPackets = numberOfPackets - 1
			counter = counter + 1
			if args.flows > 1 then
				pkt.ip4.src:set(baseIP + (counter % args.flows))
			end
			--if args.warmUp > 0 and counter == 1000 then
			--	print("Warm-up ended, no packets for " .. args.warmUp .. "s.")
			--	print(i)
			--	rateLimiter:sendN(bufs, i)
			--	lm.sleepMillis(1000 * args.warmUp)
			--	--delay =  (10000000000 / 8) * args.warmUp
			--	--buf:setDelay(0)
			--	print("Packet generation continues.")
			if (args.warmUp > 0 and counter == 946) then
				delay =  (10000000000 / 8) * args.warmUp
				buf:setDelay(delay)
				delay = 0
			--elseif (args.warmUp > 0 and counter > 946) or args.warmUp <= 0 then
			else
				delay =  delay + (10000000000 / args.fixedPacketRate / 8 - (args.packetSize + 4))
				if counter % args.burstSize == 0 then
					buf:setDelay(delay)
					delay = 0
				else
					buf:setDelay(0)
				end
			end
			if numberOfPackets <= 0 then
	                        print(i)
				rateLimiter:sendN(bufs, i)
				lm.sleepMillis(1500)
				print(counter)
				lm.stop()
				lm.sleepMillis(1500)
				os.exit(0)
				return
			end
		end
		bufs:offloadIPChecksums()
		bufs:offloadUdpChecksums()
		rateLimiter:send(bufs)
			
		if args.warmUp > 0 and counter == 945 then
			lm.sleepMillis(1000 * args.warmUp)
		end
	end
end
