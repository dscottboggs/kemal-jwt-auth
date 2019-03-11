require "logger"
require "kemal"
require "scrypt"
require "../src/kemal_jwt_auth"

# The data-type of the user is not restricted in any way. The only restriction
# lies in how it is serialized. The information which will be available as the
# `#current_user` value on the context must be an Integer, Boolean, or String
# value. So, the User must implement a `to_h` (to hash) method which returns the
# relevant information in a UserHash.
struct ExampleUser
  include JSON::Serializable
  property name : String
  property hashed_pw : Scrypt::Password

  def initialize(@name, @hashed_pw)
  end

  def to_h : UserHash
    UserHash{"name" => @name, "expiry" => (Time.now + 1.week).to_unix.to_i}
  end
end

# The only requirement of the UserCollection data-type is that it must implement
# `find_and_authenticate!` which returns the found user (of the datatype
# described  above) if authentication is successful. It should return nil if
# the user is not found or if authentication fails.
struct UserData
  @internal = [] of ExampleUser

  def initialize(users @internal); end

  def self.from_json(data) : self
    @internal.from_json data
  end

  def find_and_authenticate!(from data) : ExampleUser?
    # read in the user from the given request body
    user = Hash(String, String).from_json data
    # check for the user in the list of users, storing it in `found`
    if (found = @internal.find { |u| u.name == user["name"]? }) &&
       (found_pw = user["auth"]?) # check for the auth token, storing it in `found_pw`
      return found if found.hashed_pw == found_pw
      # return the found user, but    ^^ only if the password matches!
    end
  end
end

MockData = UserData.new(users: [
  ExampleUser.new(
    name: "test user",
    hashed_pw: Scrypt::Password.create("test user password")),
])

# In order to instantiate an instance of the handler, you have to give it the
# types of your User and a UserCollection type; then you have to give it the
# concrete user collection object.
add_handler KemalJWTAuth::Handler(UserData, ExampleUser).new users: MockData

get "/test" do |context|
  # once you do that, you can access the information from the #to_h method on a
  # user in a Kemal context, like so:
  if user = context.current_user?
    "Welcome, #{user}!"
  else
    "no user found"
  end
end

Kemal.run
