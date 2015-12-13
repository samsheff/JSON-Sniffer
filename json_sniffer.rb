require 'pcap'
require 'zlib'
require 'stringio'
require 'resolv'

cap = Pcap::Capture.open_offline(ARGV[0])

HTTP_RESPONSE = Pcap::Filter.new('tcp and src port 80', cap)

cap.each_packet do |pkt|
  next unless pkt.tcp? 
  data = pkt.tcp_data
  case pkt
  when HTTP_RESPONSE
    if data and data =~ /^(HTTP\/.*)$/ and data.include? "application/json"
      status = $1
      begin
        url = Resolv.getname(pkt.src.to_s)
      rescue
        url = pkt.src
      end
      if pkt.raw_data.include? "Content-Encoding: gzip"
        begin
          gz = Zlib::GzipReader.new(StringIO.new(pkt.raw_data.split("\r\n\r\n")))
          s = "#{pkt.time} - #{url}:#{pkt.sport} < #{status}"
          json_data = gz.read
        rescue
          s = "#{pkt.time} - #{url}:#{pkt.sport} < #{status}"
        end
      else
        s = "#{pkt.time} - #{url}:#{pkt.dport} < #{status}: #{pkt.raw_data}"
        json_data = pkt.raw_data.split("\r\n\r\n", 1)
      end
       
      File.open("./#{url}:#{pkt.sport} - #{pkt.time}.json", 'w') { |file| file.write(json_data) } if json_data
    end
  end 
  puts s if s
end
