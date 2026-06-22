# Log Injection Tests

# CVI_9409 - 日志注入
userInput = params[:user]

# Should be detected
Rails.logger.info "User login: #{userInput}"
logger.warn "Invalid input from: #{userInput}"
logger.error "Failed request: #{userInput}"
logger.debug "Query params: #{userInput}"

# False positive - hardcoded string
Rails.logger.info "Server started successfully"
logger.warn "Low disk space"
