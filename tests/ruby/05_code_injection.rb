# Ruby 代码注入 - eval/instance_eval/class_eval
user_input = params[:code]

# 漏洞
eval(user_input)
instance_eval(user_input)
class_eval(user_input)
obj.send(user_input)

# 安全
eval("1 + 1")
