# Ruby 命令注入 - 直接参数
# 测试 system/exec/IO.popen/Open3/spawn

user_input = params[:cmd]

# 漏洞
system(user_input)
system("echo #{user_input}")
system("echo " + user_input)
Kernel.system(user_input)
exec(user_input)
IO.popen(user_input)
Open3.capture3(user_input)
spawn(user_input)

# 安全
system("ls -la")
system("echo", "hello")
