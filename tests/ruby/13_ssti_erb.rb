# Server-Side Template Injection Tests

# CVI_9411 - 模板注入(SSTI)
userTemplate = params[:template]

# Should be detected
ERB.new(userTemplate).result
erb = ERB.new(userTemplate)
template = ERB.new("<h1>#{userTemplate}</h1>")

# False positive - hardcoded
ERB.new("Hello <%= name %>").result
