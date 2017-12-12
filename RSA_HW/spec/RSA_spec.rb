require_relative '../lib/RSA.rb'

RSpec.describe RSA  do 

	rsa = RSA.new(3233, 17, 413)
	keys = rsa.new_key
	rsa_rand_keys = RSA.new(keys[0], keys[1], keys[2])
	message = "lorem ipsum dolor sit amet"
	lmessage = "Lorem ipsum dolor sit amet, qui appareat mnesarchum ex"
	
	describe "testing the class functionality" do
		context "setter and getter test" do
			it "check getter of n" do
				expect(rsa.n).to eq(3233)
			end
			it "check getter of e " do
				expect(rsa.e).to eq(17)
			end
			it "check getter of d " do
				expect(rsa.d).to eq(413)
			end
		end

		context "the whole crypting test with short message" do
			it "crypt decrypt with pre defined keys" do
				expect(rsa.decrypt(rsa.encrypt(message))).to eq(message)
			end
			it "crypt decrypt with pre defined keys" do
				expect(rsa_rand_keys.decrypt(rsa_rand_keys.encrypt(message))).to eq(message)
			end
		end
		context "the whole crypting test with long message" do
			it "crypt decrypt with pre defined keys" do
				expect(rsa.decrypt(rsa.encrypt(lmessage))).to eq(lmessage)
			end
			it "crypt decrypt with pre defined keys" do
				expect(rsa_rand_keys.decrypt(rsa_rand_keys.encrypt(lmessage))).to eq(lmessage)
			end
		end
	end

end