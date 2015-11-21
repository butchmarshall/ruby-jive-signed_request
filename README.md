[![Gem Version](https://badge.fury.io/rb/ruby-jive-signed_request.svg)](http://badge.fury.io/rb/ruby-jive-signed_request)
[![Build Status](https://travis-ci.org/butchmarshall/ruby-jive-signed_request.svg?branch=master)](https://travis-ci.org/butchmarshall/ruby-jive-signed_request)

# Jive::SignedRequest

Library handling authenticating Jive signed headers and add-on registration

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'jive-signed_request'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install jive-signed_request

## Usage

To check if an authentication header is valid

```ruby
require 'jive/signed_request'

Jive::SignedRequest.authenticate("JiveEXTN algorithm=HmacSHA256&client_id=682a638ba74a4ff5fa6afa344b163e03.i&jive_url=https%3A%2F%2Fsandbox.jiveon.com%3A8443&tenant_id=b22e3911-28ef-480c-ae3b-ca791ba86952&timestamp=1436646990000&signature=GjQpEvBUoqUldgUk5bkUUrfwwUYIOcnh4IvQaDEQ4p8%3D", "8bd2952b851747e8f2c937b340fed6e1.s")
```

To create a signature (not really useful except for unit testing)

```ruby
require 'jive/signed_request'

timestamp = Time.now.to_i*1000
str = "algorithm=HmacSHA256&client_id=682a638ba74a4ff5fa6afa344b163e03.i&jive_url=https%3A%2F%2Fsandbox.jiveon.com%3A8443&tenant_id=b22e3911-28ef-480c-ae3b-ca791ba86952&timestamp=#{timestamp}";
secret = "8bd2952b851747e8f2c937b340fed6e1.s";
algorithm = "sha256";

Jive::SignedRequest.sign(str, secret, algorithm)
```

To verify an add-on registration request

```ruby
require 'jive/signed_request'

Jive::SignedRequest.validate_registration({
	clientId: '2zm4rzr9aiuvd4zhhg8kyfep229p2gce.i',
	tenantId: 'b22e3911-28ef-480c-ae3b-ca791ba86952',
	jiveSignatureURL: 'https://market.apps.jivesoftware.com/appsmarket/services/rest/jive/instance/validation/8ce5c231-fab8-46b1-b8b2-fc65deccbb5d',
	clientSecret: 'evaqjrbfyu70jlvnap8fhnj2h5mr4vus.s',
	jiveSignature: '0YqbK1nW+L+j3ppE7PHo3CvM/pNyHIDbNwYYvkKJGXU=',
	jiveUrl: 'https://sandbox.jiveon.com',
	timestamp: '2015-11-20T16:04:55.895+0000',
})
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/butchmarshall/ruby-jive-signed_request.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

