require "jwt"
require "kemal"
require "logger"

# JWT authorization middleware
class KemalJWTAuth::Handler(UsersCollection, User) < Kemal::Handler
  # Used to encrypt all JWTs
  private property secret_key : String
  @logger : Logger
  property sign_in_endpoint = "/sign_in"
  property users : UsersCollection

  def initialize(@users : UsersCollection, @secret_key = Random::Secure.base64(32), @algorithm = "HS256", @logger = Logger.new STDOUT); end

  # Load in the users from the given location, where they are in JSON format.
  # users_file may be any IO such as an open file or IO::Memory, or the string
  # contents, or a string represeting the filepath at which the data is located.
  def initialize(users_file : IO | String, @secret_key = Random::Secure.base64(32), @algorithm = "HS256", @logger = Logger.new STDOUT)
    if users_file.is_a? String
      filepath = users_file.as String
      if File.exists? filepath
        File.open filepath do |file|
          @users = UsersCollection.from_json file
        end
        return
      end
    end
    @users = UsersCollection.from_json users_file
  end

  # Kemal::Handlers must implement call, this is how Kemal communicates with
  # the middleware.
  def call(context)
    return sign_in with: context if context.request.path === @sign_in_endpoint
    load_user from: context
    call_next context
  rescue e : JWT::Error
    # This error generally occurs when a user attempts to authenticate with a
    # JWT that was generated with a different server private key, such as in
    # the case where a server's PK is generated on server launch, and the server
    # was relaunched.
    @logger.error e.message
    context.response.status_code = 403
    send_json({errors: ["Bad JWT. Reauthenticate."]})
    # do not call the next context
  end

  # Authenticate a user from JSON-encoded credentials in the request body,
  # and return to the user a JWT if they succeed the authentication challenge.
  private def sign_in(with context : HTTP::Server::Context) : HTTP::Server::Context
    if (body = context.request.body) && (user_info = @users.find_and_authenticate! body)
      return send_json({
        token:  encode(user_info.to_h),
        errors: [] of String,
      })
    end
    context.response.status_code = 403
    send_json({errors: ["Unauthorized."]})
  rescue e : JSON::ParseException
    @logger.error e
    context.response.status_code = 400
    send_json({errors: ["Bad request."]})
  end

  # Check the request headers and URL query parameters for a decryptable JWT,
  # and use User.load to set the User as the current_user attribute of the
  # context which will be recieved by other middleware.
  private def load_user(from context : HTTP::Server::Context) : Void
    if token = (context.request.headers["X-Token"]? || context.params.query["auth"]?)
      payload, header = decode jwt: token
      context.current_user = payload
    end
  end

  private def encode(data : UserHash)
    JWT.encode payload: data, key: @secret_key, algorithm: @algorithm
  end

  private def decode(jwt) : {UserHash, Hash(String, JSON::Any)}
    payload, header = JWT.decode token: jwt, key: @secret_key, algorithm: @algorithm
    pp! payload, header
    uh = UserHash.new payload.size
    payload.each { |k, v| uh[k] = v.as_s? || v.as_i? || v.as_bool? }
    {uh, header}
  end

  macro send_json(data)
    context.response.content_type = "application/json"
    context.response.print({{data}}.to_json)
    context.response.flush
    context
  end

  # Chainable setter for @sign_in_endpoint
  def signing_in_at(route)
    @sign_in_endpoint = route
    self
  end
end
