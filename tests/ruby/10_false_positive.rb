# Ruby 误报测试 - 所有安全变体
# 这些不应被检测为漏洞

system("ls -la")
system("echo", "hello")
File.read("config/database.yml")
eval("Math.sqrt(4)")
Marshal.load(File.read("cache/data"))
URI.open("https://example.com")
FileUtils.cp("a.txt", "b.txt")
FileUtils.rm_rf("/tmp/cache")
