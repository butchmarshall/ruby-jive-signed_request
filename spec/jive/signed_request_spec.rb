require 'spec_helper'

describe Jive::SignedRequest do
	it 'has a version number' do
		expect(Jive::SignedRequest::VERSION).not_to be nil
	end

	describe '::Jive::SignedRequest.authenticate' do
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

	describe '::Jive::SignedRequest.validate_registration' do
		it 'should validate using the provided sdk data', :focus => true do
			result = ::Jive::SignedRequest.validate_registration({  
				#code: "nki1dxrtl3r2q3kkgorwfkrmik234ppw.c",
				#scope: "uri:/api",
				clientId: "i5j15eikcd5u2xntgk5zu4lt93zkgx6z.i",
				tenantId: "0ee9ae5c-4702-49eb-a716-3d46de4b10d3",
				jiveSignatureURL: "https://market.apps.jivesoftware.com/appsmarket/services/rest/jive/instance/validation/29c38d1a-9c8a-4ec5-9b55-56fc44a5a402",
				clientSecret: "7wmyigctxbopc22jo7u4xorxsn2m9r04.s",
				jiveSignature: "dtuW522kpoayRLFkPq6l3MOXxoKwfyNHsgGMlitr9PM=",
				jiveUrl: "http://ws-z0-120493.jiveland.com:8080",
				timestamp: "2013-07-12T15:28:46.493Z"  
			})
			expect(result).to eq(true)
		end
		
		it 'should validate authentic registrations', :focus => true do
			result = ::Jive::SignedRequest.validate_registration({
				clientId: '2zm4rzr9aiuvd4zhhg8kyfep229p2gce.i',
				tenantId: 'b22e3911-28ef-480c-ae3b-ca791ba86952',
				jiveSignatureURL: 'https://market.apps.jivesoftware.com/appsmarket/services/rest/jive/instance/validation/8ce5c231-fab8-46b1-b8b2-fc65deccbb5d',
				clientSecret: 'evaqjrbfyu70jlvnap8fhnj2h5mr4vus.s',
				jiveSignature: '0YqbK1nW+L+j3ppE7PHo3CvM/pNyHIDbNwYYvkKJGXU=',
				jiveUrl: 'https://sandbox.jiveon.com',
				timestamp: '2015-11-20T16:04:55.895+0000',
			})
			expect(result).to eq(true)
		end
		
		it 'should not validate bad registrations', :focus => true do
			result = ::Jive::SignedRequest.validate_registration({
				clientId: '2zm4rzr9aiuvd4zhhg8kyfep229p2gce.i',
				tenantId: 'b22e3911-28ef-480c-ae3b-ca791ba86952',
				jiveSignatureURL: 'https://market.apps.jivesoftware.com/appsmarket/services/rest/jive/instance/validation/8ce5c231-fab8-46b1-b8b2-fc65deccbb5d',
				clientSecret: 'evaqjrbfyu70jlvnap8fhnj2h5mr4vus.s',
				jiveSignature: '0YqbK1nW+L+j3ppE7PHo3CvM/pNyHIDbNwYYvkKJGXU=',
				jiveUrl: 'https://bad-sandbox.jiveon.com',
				timestamp: '2015-11-20T16:04:55.895+0000',
			})
			expect(result).to eq(false)
		end
	end	
end
