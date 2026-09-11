# XPath Injection Tests

# CVI_9412 - XPath注入
userName = params[:name]

# Should be detected
doc.xpath("//user[name='#{userName}']")
doc.xpath("//*[@id='#{userName}']")

# False positive - hardcoded
doc.xpath("//users/user")
