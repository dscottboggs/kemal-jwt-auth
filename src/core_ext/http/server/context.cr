require "../../../kemal_jwt_auth"

class HTTP::Server
  class Context
    property! current_user : UserHash
  end
end
