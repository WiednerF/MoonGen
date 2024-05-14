--- Replay a pcap file.

local mg      = require "moongen"
local device  = require "device"
local memory  = require "memory"
local stats   = require "stats"
local log     = require "log"
local pcap    = require "pcap"
local limiter = require "software-ratecontrol"

function configure(parser)
	parser:argument("dev", "Device to use."):args(1):convert(tonumber)
	parser:argument("files", "Files to replay."):args("+")
	parser:option("-r --rate-multiplier", "Speed up or slow down replay, 1 = use intervals from file, default = replay as fast as possible"):default(0):convert(tonumber):target("rateMultiplier")
	parser:option("-s --buffer-flush-time", "Time to wait before stopping MoonGen after enqueuing all packets. Increase for pcaps with a very low rate."):default(10):convert(tonumber):target("bufferFlushTime")
	parser:flag("-l --loop", "Repeat pcap file.")
	parser:option("-ln --loop-number", "Number of times to loop through the file"):default(1):convert(tonumber):target("loopTime")
	parser:flag("-noEth --noEthernetHeader", "The PCAP files have no Ethernet Header, create one")
	local args = parser:parse()
	return args
end

function master(args)
	local dev = device.config{port = args.dev}
	device.waitForLinks()
	local rateLimiter
	if args.rateMultiplier > 0 then
		rateLimiter = limiter:new(dev:getTxQueue(0), "custom")
	end
	local replayer = mg.startTask("replay", dev:getTxQueue(0), args.files, args.loop, rateLimiter, args.rateMultiplier, args.bufferFlushTime, args.noEthernetHeader, args.loopTime)
	stats.startStatsTask{txDevices = {dev}}
	replayer:wait()
	mg:stop()
	mg.waitForTasks()
end

function replay(queue, files, loop, rateLimiter, multiplier, sleepTime, noEthernetHeader, loopTime)
	local mempool
	if noEthernetHeader then
		mempool = memory.createMemPool{n=4096,func=function(buf)
			buf:getEthernetPacket():fill{}
		end}
	else
		mempool = memory.createMemPool{n=4096}
	end
	local bufs = mempool:bufArray()
	local pcapFiles = {}
	for index,value in ipairs(files) do
		pcapFiles[index] = pcap:newReader(value)
	end
	local pcapFile = pcapFiles[1]
	local loopTime = loopTime
	local position  = 1
	local prev = 0
	local linkSpeed = queue.dev:getLinkStatus().speed
	while mg.running() do
		local n = pcapFile:read(bufs,2048,noEthernetHeader)
		if n > 0 then
			if rateLimiter ~= nil then
				if prev == 0 then
					prev = bufs.array[0].udata64
				end
				for i = 1, n  do
					local buf = bufs[i]
					-- ts is in microseconds
					local ts = buf.udata64
					if prev > ts then
						ts = prev
					end
					local delay = ts - prev
					delay = tonumber(delay * 10^3) / multiplier -- nanoseconds
					delay = delay / (8000 / linkSpeed) -- delay in bytes
					buf:setDelay(delay)
					prev = ts
				end
			end
			if rateLimiter then
				rateLimiter:sendN(bufs, n)
			else
				queue:sendN(bufs, n)
			end
		else
			if position < #files then
					position = position + 1
					prev = 0
					pcapFile = pcapFiles[position]
			else
				if loop then
					for _,value in ipairs(pcapFiles) do
						value:reset()
					end
					pcapFile = pcapFiles[1]
					prev = 0
					position = 1
				elseif loopTime > 1:
					for _,value in ipairs(pcapFiles) do
						value:reset()
					end
					pcapFile = pcapFiles[1]
					prev = 0
					position = 1
					loopTime = loopTime - 1
				else
					break
				end
			end
		end
	end
	log:info("Enqueued all packets, waiting for %d seconds for queues to flush", sleepTime)
	mg.sleepMillisIdle(sleepTime * 1000)
end

