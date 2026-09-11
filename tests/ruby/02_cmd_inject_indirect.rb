# Ruby 命令注入 - 间接传递
cmd = params[:cmd]

# 漏洞 - 间接传递
clean_cmd = sanitize(cmd)
system(clean_cmd)

# 漏洞 - 拼接
cmd2 = "ls " + params[:path]
system(cmd2)

# 漏洞 - 函数返回值
def get_command(user_input)
  "cat " + user_input
end
system(get_command(user_input))
