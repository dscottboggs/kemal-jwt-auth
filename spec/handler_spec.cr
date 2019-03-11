require "./spec_helper"

class KemalJWTAuth::Handler(UsersCollection, User) < Kemal::Handler
  {% for method in @type.methods
                     .select { |m| m.visibility == :private }
                     .reject { |m| m.name.ends_with? '=' } %}
    def _test__{{method.name.id}}(*args, **opts)
      {{method.name.id}}(*args, **opts)
    end
  {% end %}
end

struct ServerResponse
  include JSON::Serializable
  property token : String?
  property errors : Array(String)
end

SignInData = {name: "test user", auth: "test user password"}

def json_body_in(http response : String)
  response.split("\r\n").select { |line| line[0]? == '{' }.first
end

describe KemalJWTAuth do
  it "initializes properly" do
    instance = KemalJWTAuth::Handler(UserData, ExampleUser).new MockData
    instance.users.@internal.map { |u| u.name }.should eq MockData.@internal.map { |u| u.name }
  end
  describe "the sign-in process" do
    it "works" do
      instance = KemalJWTAuth::Handler(UserData, ExampleUser).new MockData
      response_storage = IO::Memory.new
      request = HTTP::Request.new "POST", "/sign_in", body: SignInData.to_json
      response = HTTP::Server::Response.new response_storage
      context = HTTP::Server::Context.new request, response

      instance._test__sign_in(with: context).should eq context
      if context.response.status_code != 200
        response_data = ServerResponse.from_json response_storage.rewind
        fail response_data.errors.first
      end
      context.response.status_code.should eq 200
      response_data = ServerResponse.from_json json_body_in http: response_storage.rewind.gets_to_end
      response_data.token.should_not be_nil
      response_data.errors.empty?.should be_true
    end
    it "denies a bad request" do
      instance = KemalJWTAuth::Handler(UserData, ExampleUser).new MockData
      response_storage = IO::Memory.new
      request = HTTP::Request.new "POST", "/sign_in", body: "not JSON at all!"
      response = HTTP::Server::Response.new response_storage
      context = HTTP::Server::Context.new request, response

      instance._test__sign_in(with: context).should eq context
      context.response.status_code.should eq 400
      response_data = ServerResponse.from_json json_body_in http: response_storage.rewind.gets_to_end
      response_data.errors.first?.should eq "Bad request."
    end
    it "denies bad authorization" do
      instance = KemalJWTAuth::Handler(UserData, ExampleUser).new MockData
      response_storage = IO::Memory.new
      request = HTTP::Request.new "POST", "/sign_in", body: {name: "test user", auth: "not the actual password"}.to_json
      response = HTTP::Server::Response.new response_storage
      context = HTTP::Server::Context.new request, response

      instance._test__sign_in(with: context).should eq context
      context.response.status_code.should eq 403
      response_data = ServerResponse.from_json json_body_in http: response_storage.rewind.gets_to_end
      response_data.errors.first?.should eq "Unauthorized."
    end
  end
  describe "#encode and #decode" do
    it "works" do
      instance = KemalJWTAuth::Handler(UserData, ExampleUser).new MockData
      instance._test__decode(
        instance._test__encode(MockData.@internal.first.to_h)
      )[0].should eq MockData.@internal.first.to_h
    end
  end
  describe "the reauthentication process" do
    it "loads from a header" do
      instance = KemalJWTAuth::Handler(UserData, ExampleUser).new MockData

      user_info = HTTP::Headers.new
      user_info["X-Token"] = instance._test__encode(MockData.@internal.first.to_h)

      request = HTTP::Request.new "POST", "/sign_in", user_info
      response_storage = IO::Memory.new
      response = HTTP::Server::Response.new response_storage
      context = HTTP::Server::Context.new request, response

      instance._test__load_user(context)
      context.current_user["name"].should eq "test user"
      context.current_user["expiry"].as(Int32).should be_close((Time.now + 1.week).to_unix.to_i, 1)
    end
    it "loads from a query parameter" do
      instance = KemalJWTAuth::Handler(UserData, ExampleUser).new MockData

      request = HTTP::Request.new "POST", "/sign_in?auth=#{instance._test__encode(MockData.@internal.first.to_h)}"
      response_storage = IO::Memory.new
      response = HTTP::Server::Response.new response_storage
      context = HTTP::Server::Context.new request, response

      instance._test__load_user(context)
      context.current_user["name"].should eq "test user"
      context.current_user["expiry"].as(Int32).should be_close((Time.now + 1.week).to_unix.to_i, 1)
    end
    it "throws a JWT::Error on an invalid JWT" do
      instance = KemalJWTAuth::Handler(UserData, ExampleUser).new MockData

      request = HTTP::Request.new "POST", "/sign_in?auth=some-nonsense"
      response_storage = IO::Memory.new
      response = HTTP::Server::Response.new response_storage
      context = HTTP::Server::Context.new request, response

      expect_raises JWT::Error do
        instance._test__load_user(context)
      end
      context.current_user?.should be_nil
    end
  end
end
