# Deliberately vulnerable Ruby fixture.
require 'digest'

# VULN: SQL Injection — string interpolation into execute()
def get_user(db, params)
  id = params[:id]
  db.execute("SELECT * FROM users WHERE id = #{id}")
end

# VULN: Command Injection — interpolation into system()
def ping(params)
  system("ping -c 1 #{params[:host]}")
end

# VULN: Hardcoded Secret
AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
