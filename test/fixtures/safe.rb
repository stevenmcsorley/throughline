# Idiomatic, safe Ruby. Any finding here is a false positive.
require 'digest'

ALLOWED_HOSTS = ['api.internal.example'].freeze

def get_user(db, params)
  # Bound parameter — the driver escapes it.
  db.execute('SELECT * FROM users WHERE id = ?', [params[:id]])
end

def ping(params)
  # Argument list, so no shell parses the value.
  host = params[:host]
  system('ping', '-c', '1', host) if ALLOWED_HOSTS.include?(host)
end

def digest(data)
  Digest::SHA256.hexdigest(data)
end

AWS_ACCESS_KEY = ENV['AWS_ACCESS_KEY']
