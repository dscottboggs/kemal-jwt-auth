# Kemal JWT Authentication

Drop-in authentication middleware for [Kemal](http://kemalcr.com/), independent
of user model. See [example.cr](https://github.com/dscottboggs/kemal-jwt-auth/blob/master/example/example.cr)
for a full example.

### TL;DR:

```crystal
require "kemal"
require "kemal_jwt_auth"
# you can use your existing users collection data-structure.
require "./my_users"

# Your `MyUsers` must include the `KemalJWTAuth::UsersCollection` module
collection = MyUsers.default_config

add_handler KemalJWTAuth::Handler.new users: collection

get "/test" do |context|
  if user = context.current_user?
    "Welcome, #{user}!"
  else
    "no user found"
  end
end

Kemal.run
```

## JavaScript companion

There is a JavaScript companion library to make using this library with an SPA
or other JavaScript client a cinch. See [the client repository](https://github.com/dscottboggs/kemal-jwt-auth-companion)
for more information

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     kemal_jwt_auth:
       github: dscottboggs/kemal_jwt_auth
       version: ~> 1.0
   ```

2. Run `shards install`

## Contributing

1. Fork it (<https://github.com/dscottboggs/kemal_jwt_auth/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [D. Scott Boggs](https://github.com/dscottboggs) - creator and maintainer
