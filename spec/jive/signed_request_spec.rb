require 'spec_helper'

describe Jive::SignedRequest do
	it 'has a version number' do
		expect(Jive::SignedRequest::VERSION).not_to be nil
	end

	it 'should sign correctly' do
		str = "algorithm=HmacSHA256&client_id=682a638ba74a4ff5fa6afa344b163e03.i&jive_url=https%3A%2F%2Fsandbox.jiveon.com%3A8443&tenant_id=b22e3911-28ef-480c-ae3b-ca791ba86952&timestamp=1436646363000";
		algorithm = "sha256";
		secret = "8bd2952b851747e8f2c937b340fed6e1.s";
		expected = "B7bRJn+lWS6CrY+Hq/pr8uCSevDUNmMIqKEq+ulLoG4=";

		result = ::Jive::SignedRequest.sign(str, secret, algorithm)

		expect(result).to eq(expected)
	end
	
	it 'should authenticate correctly' do
		# First build a valid signature
		timestamp = Time.now.to_i*1000
		str = "algorithm=HmacSHA256&client_id=682a638ba74a4ff5fa6afa344b163e03.i&jive_url=https%3A%2F%2Fsandbox.jiveon.com%3A8443&tenant_id=b22e3911-28ef-480c-ae3b-ca791ba86952&timestamp=#{timestamp}";
		algorithm = "sha256";
		secret = "8bd2952b851747e8f2c937b340fed6e1.s";

		signature = ::Jive::SignedRequest.sign(str, secret, algorithm)

		# Build a valid Authorization header
        authorization_header = "JiveEXTN #{str}&signature=#{CGI::escape(signature)}";

		result = ::Jive::SignedRequest.authenticate(authorization_header, secret)

		expect(result).to eq(true)
	end

	it 'should authenticate even though 4 minutes old' do
		# First build a valid signature
		timestamp = (Time.now.to_i-(4*60))*1000 
		str = "algorithm=HmacSHA256&client_id=682a638ba74a4ff5fa6afa344b163e03.i&jive_url=https%3A%2F%2Fsandbox.jiveon.com%3A8443&tenant_id=b22e3911-28ef-480c-ae3b-ca791ba86952&timestamp=#{timestamp}";
		algorithm = "sha256";
		secret = "8bd2952b851747e8f2c937b340fed6e1.s";

		signature = ::Jive::SignedRequest.sign(str, secret, algorithm)

		# Build a valid Authorization header
        authorization_header = "JiveEXTN #{str}&signature=#{CGI::escape(signature)}";

		result = ::Jive::SignedRequest.authenticate(authorization_header, secret)

		expect(result).to eq(true)
	end

	it 'should raise an ArgumentError if Authentication header 6 minutes old' do
		# First build a valid signature
		timestamp = (Time.now.to_i-(6*60))*1000 
		str = "algorithm=HmacSHA256&client_id=682a638ba74a4ff5fa6afa344b163e03.i&jive_url=https%3A%2F%2Fsandbox.jiveon.com%3A8443&tenant_id=b22e3911-28ef-480c-ae3b-ca791ba86952&timestamp=#{timestamp}";
		algorithm = "sha256";
		secret = "8bd2952b851747e8f2c937b340fed6e1.s";

		signature = ::Jive::SignedRequest.sign(str, secret, algorithm)

		# Build a valid Authorization header
        authorization_header = "JiveEXTN #{str}&signature=#{CGI::escape(signature)}";

		expect { ::Jive::SignedRequest.authenticate(authorization_header, secret) }.to raise_error(ArgumentError)
	end

end
