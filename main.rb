require "pathname"

def decode(iphex)
  [iphex].pack("H*").unpack("C*").join(".")
end

def make_dot_from_logfile(file)
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
        default_node = "root-servers.net"
        default_zone = "."
      when /(\d+\.){3}/
        _, ip = line.chomp.split
        node = default_node.to_sym
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
        node = label =~ /gtld/ ? :"gtld.servers.net" : label.to_sym
        ip = decode(value)
        g[from_node] << [:A, node, ttl]
        g[from_node].uniq!
        ip2node[ip] = node
      when "ns"
        node = value =~ /gtld/ ? :"gtld.servers.net" : value.to_sym

        g[from_node] << [:ns, node, ttl]
        g[from_node].uniq!
        zones[node] << label
      when "cname"
        node = value =~ /gtld/ ? :"gtld.servers.net" : value.to_sym
        to_node = label.to_sym
        g[from_node] << [:cname, node, ttl]
        g[from_node].uniq!
        g[node] << [:alias, to_node, ttl]
      end
    end
  end

  logfile.sub_ext(".dot").open(mode = "w") do |fh|
    fh.puts "digraph djbdns {"
    ip2node.values.uniq.each do |node|
      zone = zones[node].uniq.join("\\n")
      fh.puts "\t\"#{node}\" [label = \"#{zone}\\n#{node}\"];"
    end

    g.each do |from_node, nodes|
      nodes.each do |type, to_node, ttl|
        if type == :A
          fh.puts "\t\"#{from_node}\" -> \"#{to_node}\" [label = \"#{type}\\n#{ttl}\"];"
        else
          fh.puts "\t\"#{from_node}\" -> \"#{to_node}\" [label = \"#{type}\\n#{ttl}\", style=\"dashed\"];"
        end
      end
    end

    fh.puts "}"
  end

  dot = logfile.sub_ext(".dot")
  pdf = logfile.sub_ext(".pdf")
  `dot -Tpdf -o #{pdf} #{dot}`
end

ARGV.each do |logfile|
  next unless File.extname(logfile) == ".log"
  make_dot_from_logfile(logfile)
end
