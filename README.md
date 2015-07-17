# Jive::SignedRequest

Verify that a signed Jive Authorization header is valid

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'jive-SignedRequest'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install jive-signed_request

## Usage

To check if a Authentication header is valid

```ruby
require 'jive/signed_request'

Jive::SignedRequest.authenticate("JiveEXTN algorithm=HmacSHA256&client_id=682a638ba74a4ff5fa6afa344b163e03.i&jive_url=https%3A%2F%2Fsandbox.jiveon.com%3A8443&tenant_id=b22e3911-28ef-480c-ae3b-ca791ba86952&timestamp=1436646990000&signature=GjQpEvBUoqUldgUk5bkUUrfwwUYIOcnh4IvQaDEQ4p8%3D", "8bd2952b851747e8f2c937b340fed6e1.s")
```

To sign 

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/butchmarshall/jive-SignedRequest.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

