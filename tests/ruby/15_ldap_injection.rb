# LDAP Injection Tests

# CVI_9413 - LDAP注入
userFilter = params[:filter]

# Should be detected
ldap.search(:filter => "(cn=#{userFilter})")
ldap.search(filter: "(uid=#{userFilter})")

# False positive - hardcoded
ldap.search(:filter => "(objectClass=user)")
