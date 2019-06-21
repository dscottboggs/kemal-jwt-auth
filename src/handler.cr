require "jwt"
require "kemal"
require "logger"
require "./users_collection"

# JWT authorization middleware
class KemalJWTAuth::Handler < Kemal::Handler
  property sign_in_endpoint = "/sign_in"
  property users : UsersCollection
  property logger : Logger = Logger.new STDOUT
  property algorithm : JWT::Algorithm = JWT::Algorithm::HS256
  # Used to encrypt all JWTs
  @secret_key : String

  # Load in the users from the given location, where they are in JSON format.
  def initialize(@users : UsersCollection, @secret_key : String = Random::Secure.base64(32))
  end

  # :ditto:
  def self.new(users path : Path, secret_key : String = Random::Secure.base64(32))
    File.open path.to_s do |file|
      users = UsersCollection.from_json file
    end
    new users, secret_key
  end

  # :ditto:
  def self.new(users content : IO | String, secret_key : String = Random::Secure.base64(32))
    new UsersCollection.from_json(content), secret_key
  end

  # Kemal::Handlers must implement call, this is how Kemal communicates with
  # the middleware.
  def call(context : HTTP::Server::Context) : Nil
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
    send_json({errors: {"Bad JWT. Reauthenticate."}}, to: context)
    # do not call the next context
  end

  # Authenticate a user from JSON-encoded credentials in the request body,
  # and return to the user a JWT if they succeed the authentication challenge.
  private def sign_in(with context : HTTP::Server::Context) : HTTP::Server::Context
    if (body = context.request.body) && (user_info = @users.find_and_authenticate! body)
      return send_json({
        token:  encode(user_info.to_h),
        errors: [] of String,
      }, to: context)
    end
    context.response.status_code = 403
    send_json({errors: {"Unauthorized."}}, to: context)
  rescue e : JSON::ParseException
    @logger.error e
    context.response.status_code = 400
    send_json({errors: {"Bad request."}}, to: context)
  end

  # Check the request headers and URL query parameters for a decryptable JWT,
  # and use User.load to set the User as the current_user attribute of the
  # context which will be recieved by other middleware.
  private def load_user(from context : HTTP::Server::Context) : Nil
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
    user_hash = UserHash.new payload.size
    payload.each { |k, v| user_hash[k] = v.as_s? || v.as_i? || v.as_bool? }
    {user_hash, header}
  end

  private def send_json(data, to context : HTTP::Server::Context) : HTTP::Server::Context
    context.response.content_type = "application/json"
    context.response.print data.to_json
    context.response.flush
    context
  end

  # Chainable setter for @sign_in_endpoint
  def signing_in_at(route : String)
    @sign_in_endpoint = route
    self
  end
end
