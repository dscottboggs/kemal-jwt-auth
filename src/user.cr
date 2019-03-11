abstract struct User
  abstract def to_h : UserHash
end

alias UserHash = Hash(String, (String | Int32 | Nil | Bool))
