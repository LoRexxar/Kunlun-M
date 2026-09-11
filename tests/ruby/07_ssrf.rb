# Ruby SSRF
url = params[:url]

# 漏洞
response = Net::HTTP.get(URI.parse(url))
URI.open(url)
HTTParty.get(url)

# 安全
Net::HTTP.get(URI.parse("https://api.example.com/health"))
