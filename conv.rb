require "pathname"

def decode(iphex)
  [iphex].pack("H*").unpack("C*").join(".")
end

def make_csv_from_logfile(file)
  logfile = Pathname.new(file)

  switch = 0
  root_prefix = "a"
  default_node = ""
  default_zone = ""

  g = Hash.new { |h, k| h[k] = [] }
  ip2node = {}
  ips = {}
  zones = Hash.new { |h, k| h[k] = [] }

  logfile.each_line do |line|
    case switch
    when 0
      if line =~ /^Jun/
        switch = 2
        next
      end

      case line
      when /vip.symantec.com/
        default_node = "ns.preset.vip.symantec.com"
        default_zone = "vip.symantec.com"
      when /googledomains.com/
        default_node = "ns.preset.googledomains.com"
        default_zone = "googledomains.com"
      when /roots/
        default_zone = "."
      when /(\d+\.){3}/
        _, ip = line.chomp.split
        default_node = root_prefix + ".root-servers.net"
        node = default_node
        root_prefix = root_prefix.succ
        zones[node] << default_zone
        ip2node[ip] = node
      end
    when 2
      next unless line =~ /\s+rr\s/

      _, from_ip, ttl, type, label, value = line.chomp.split
      next unless type =~ /^(A|ns|cname)$/

      from_node = ip2node[from_ip]
      raise "bad record #{line}" if from_node.nil?

      case type
      when "A"
        node = label
        ip = decode(value)
        g[from_node] << [:A, node, ttl]
        ip2node[ip] = node
      when "ns"
        node = value

        g[from_node] << [:ns, node, ttl]
        zones[node] << label
      when "cname"
        node = value
        to_node = label
        g[from_node] << [:cname, node, ttl]
        g[node] << [:alias, to_node]
      end
    end
  end

  logfile.sub_ext(".csv").open(mode = "w") do |fh|
    fh.puts "zone, from_node, from_ip, ttl, type, to_node, to_ip"
    g.keys.sort_by { |n| [zones[n], n] }.each do |from_node|
      zone = zones[from_node].uniq.join(";")
      g[from_node].sort.each do |type, to_node, ttl|
        from_ip = ip2node.keys.select { |ip| ip2node[ip] == from_node }.join(";")
        to_ip = ip2node.keys.select { |ip| ip2node[ip] == to_node }.join(";")
        fh.puts [zone, from_node, from_ip, ttl, type, to_node, to_ip].join(",")
      end
    end
  end
end

ARGV.each do |logfile|
  next unless File.extname(logfile) == ".log"
  make_csv_from_logfile(logfile)
end
