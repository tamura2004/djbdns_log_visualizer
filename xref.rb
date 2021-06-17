require "pathname"

g = Hash.new { |h, k| h[k] = [] }

root = Pathname.new("src")
root.find do |path|
  next unless path.extname == ".c"
  from = path.basename(".c").to_s
  path.each_line do |line|
    next unless line =~ /#include/
    to = line.scan(/^\#include ["<](.*)..[">]$/).first.first
    g[from] << to
  end
end

open("xref.dot", "w") do |fh|
  fh.puts "digraph djbdns {"
  q = ["dnscache"]
  seen = {}
  while q.size > 0
    v = q.shift
    g[v].each do |nv|
      key = "#{v}@#{nv}"
      next if seen[key]
      seen[key] = true
      fh.puts "\"#{v}\" -> \"#{nv}\";"
      q << nv
    end
  end
  fh.puts "}"
end

`dot -Tpdf -o xref.pdf xref.dot`
