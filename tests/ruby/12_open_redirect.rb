# Open Redirect Tests

# CVI_9410 - 开放重定向
targetUrl = params[:redirect_to]

# Should be detected
redirect_to targetUrl
redirect_to params[:next]

# False positive - hardcoded string
redirect_to "/dashboard"
redirect_to root_path
