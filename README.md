# Kemal JWT Authentication

Drop-in authentication middleware for [Kemal](http://kemalcr.com/), independent
of user model. See [example.cr](https://github.com/dscottboggs/kemal-jwt-auth/blob/master/example/example.cr)
for a full example.

### TL;DR:

```crystal
require "kemal"
require "kemal_jwt_auth"

add_handler KemalJWTAuth::Handler(UserCollectionType, YourUserType).new users: collection

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
       github: your-github-user/kemal_jwt_auth
   ```

2. Run `shards install`

## Contributing

1. Fork it (<https://github.com/your-github-user/kemal_jwt_auth/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [D. Scott Boggs](https://github.com/your-github-user) - creator and maintainer
