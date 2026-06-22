# Ruby XSS
user_input = params[:name]

# 漏洞
raw(user_input)
"<div>#{user_input}</div>".html_safe
content_tag(:div, user_input)

# 安全
ERB::Util.html_escape(user_input)
content_tag(:div, ERB::Util.html_escape(user_input))
