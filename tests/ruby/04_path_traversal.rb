# Ruby 路径遍历 - File/IO/Dir
filename = params[:file]

# 漏洞
File.read(filename)
File.open(filename, 'r')
File.write(filename, "data")
File.delete(filename)
IO.read("/tmp/#{params[:path]}/file")
Dir.glob(params[:pattern])

# 安全
File.read("config.yml")
File.open("/etc/hosts", 'r')
