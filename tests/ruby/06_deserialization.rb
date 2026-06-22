# Ruby 反序列化
user_data = params[:data]

# 漏洞
Marshal.load(user_data)
YAML.load(user_data)

# 安全
YAML.safe_load(user_data)
