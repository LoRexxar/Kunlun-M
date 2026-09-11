# Ruby SQL注入 - ActiveRecord
user_input = params[:id]
user_name = params[:name]

# 漏洞 - string interpolation
ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = #{user_input}")
ActiveRecord::Base.find_by_sql("SELECT * FROM users WHERE name = '#{user_name}'")
User.where("name = '#{user_input}'")
User.delete_all("id = #{user_input}")
User.update_all("name = '#{user_name}'", "id = 1")

# 安全 - parameterized
User.find_by(id: params[:id])
User.where(id: params[:id])
