#/usr/bin/env ruby

require 'frasm'

d = Frasm::DistormDecoder.new

d.decode("ABCDEFGHIJKLMNOPQRSTUVWXYZ").each do |l|
	puts "#{l.mnem} #{l.size} #{l.offset} #{l.raw}"
end
