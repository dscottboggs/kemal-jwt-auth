module KemalJWTAuth::UsersCollection
  # A UsersCollection must return an authenticated user from this method, or
  # nil in the case of failed authentication. The body is the body received
  # from `HTTP::Request#body` -- a non-nil IO (in the case where the body
  # is nil, this method is not called.)
  abstract def find_and_authenticate!(body : IO)
  # It actually needs `self.from_json` but you can't define an abstract class
  # method
  abstract def to_json
end
