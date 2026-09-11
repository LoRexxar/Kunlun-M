# Unsafe Deserialization Tests

# CVI_9414 - 不安全反序列化
userData = params[:data]

# Should be detected
YAML.load(userData)
Marshal.load(userData)
Oj.load(userData)

# False positive - safe alternative
YAML.safe_load(userData)
YAML.load_file("config.yml")
