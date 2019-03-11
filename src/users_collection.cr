abstract struct UsersCollection(U)
  abstract def find_and_authenticate!(from body : IO) : U?

  def self.from_json(data : IO | String) : self
    raise "implement me!"
  end
end
