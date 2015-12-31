require "jive/signed_request/version"
require "base64"
require "openssl"
require "cgi"
require "time"

module Jive # :nodoc:
	module SignedRequest # :nodoc:
		module_function

		# Sign a string with a secret
		#
		# Sign a string with a secret and get the signature
		#
		# * *Args*    :
		#   - +string+ -> the string to sign
		#   - +secret+ -> the secret to use
		# * *Returns* :
		#   - the signature
		# * *Raises* :
		#   - +ArgumentError+ -> if no algorithm passed and algorithm could not be derived from the string
		#
		def sign(string, secret, algorithm = nil)
			plain = ::Base64.decode64(secret.gsub(/\.s$/,''))
			
			# if no override algorithm passed try and extract from string
			if algorithm.nil?
				paramMap = ::CGI.parse string

				if !paramMap.has_key?("algorithm")
					raise ArgumentError, "missing algorithm"
				end

				algorithm = paramMap["algorithm"].first.gsub(/^hmac/i,'')
			end
			
			hmac = ::OpenSSL::HMAC.digest(algorithm, plain, string)
			Base64::encode64(hmac).gsub(/\n$/,'')
		end

		# Authenticate an authorization header
		#
		# Authenticates that an authorization header sent by Jive is valid given an apps secret
		#
		# * *Args*    :
		#   - +authorization_header+ -> the entire Authorization header sent by Jive
		#   - +client_secret+ -> the client secret to authenticate the header with
		# * *Returns* :
		#   - the signature
		# * *Raises* :
		#   - +ArgumentError+ -> if the authorization_header does not contain JiveEXTN
		#   - +ArgumentError+ -> if the heauthorization_header does not contain all the required parameters
		#   - +ArgumentError+ -> if the heauthorization_header has expired (more than 5 minutes old)
		#
		def authenticate(authorization_header, client_secret)
			# Validate JiveEXTN part of header
			if !authorization_header.match(/^JiveEXTN/)
				raise ArgumentError, "Jive authorization header is not properly formatted, must start with JiveEXTN"
			end

			paramMap = ::CGI.parse authorization_header.gsub(/^JiveEXTN\s/,'')

			# Validate all parameters are passed from header
			if !paramMap.has_key?("algorithm") ||
				!paramMap.has_key?("client_id") ||
				!paramMap.has_key?("jive_url") ||
				!paramMap.has_key?("tenant_id") ||
				!paramMap.has_key?("timestamp") ||
				!paramMap.has_key?("signature")
				raise ArgumentError, "Jive authorization header is partial"
			end

			# Validate timestamp is still valid
			timestamp = Time.at(paramMap["timestamp"].first.to_i/1000)
			secondsPassed = Time.now - timestamp

			if secondsPassed < 0 || secondsPassed > (5*60)
				raise ArgumentError, "Jive authorization is rejected since it's #{ secondsPassed } seconds old (max. allowed is 5 minutes)"
			end

			self.sign(authorization_header.gsub(/^JiveEXTN\s/,'').gsub(/\&signature[^$]+/,''), client_secret) === paramMap["signature"].first
		end
		
		# Validates an app registration
		#
		# Validates an app registration came from where it claims via jiveSignatureURL
		#
		# * *Args*    :
		#   - +validationBlock+ -> the request body of the registration
		#   - +args+ -> additional arguments
		# * *Returns* :
		#   - boolean
		#
		def validate_registration(validationBlock, *args)
			options = ((args.last.is_a?(Hash)) ? args.pop : {})

			require "open-uri"
			require "net/http"
			require "openssl"

			jive_signature_url = validationBlock[:jiveSignatureURL]
			jive_signature = validationBlock[:jiveSignature]

			validationBlock.delete(:jiveSignature)

			if !validationBlock[:clientSecret].nil?
				validationBlock[:clientSecret] = Digest::SHA256.hexdigest(validationBlock[:clientSecret])
			end

			uri = URI.parse(jive_signature_url)
			http = Net::HTTP.new(uri.host, uri.port)
			http.use_ssl = true
			http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl? && !options[:verify_ssl]

			buffer = ''
			validationBlock = validationBlock.sort

			(validationBlock.respond_to?(:to_h) ? validationBlock.to_h : Hash[validationBlock] ).each_pair { |k,v|
				buffer = "#{buffer}#{k}:#{v}\n"
			}

			request = Net::HTTP::Post.new(uri.request_uri)
			request.body = buffer

			request["X-Jive-MAC"] = jive_signature
			request["Content-Type"] = "application/json"

			response = http.request(request)

			(response.code.to_i === 204)
		end
 	end
end
