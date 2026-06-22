# Ruby 任意文件操作 - FileUtils
src = params[:src]
dest = params[:dest]

# 漏洞
FileUtils.cp(src, dest)
FileUtils.rm_rf(params[:dir])
FileUtils.mkdir_p(params[:path])
FileUtils.touch(params[:file])
FileUtils.mv(src, dest)

# 安全
FileUtils.cp("a.txt", "b.txt")
FileUtils.rm_rf("/tmp/cache")
