require "./core_ext/**"
require "./*"

# This is the format stored in the JWT for later retrieval -- it is a limited
# subset of JSON. If you can't store your data in this structure, you have to
# serialize it in some other way, then store that as a string member.
alias UserHash = Hash(String, (String | Int32 | Nil | Bool))

module KemalJWTAuth
  VERSION = "0.1.0"
end
