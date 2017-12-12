require 'prime'

class RSA
   def initialize n, e, d
      #initializes this instance of RSA with a n,e and d variables of type int. 'n','e' are the public key and 'd' is the private one. This n,e,d should be used when encrypting and decrypting the message
      @n = n
      @e = e
      @d = d
   end

   def pow_mod m, pow, mod
      if pow == 0
         return 1
      elsif pow == 1
         return m
      end
      res = m
      for i in 1..(pow - 1)
         res = (res * m) % mod
      end
      return res
   end
   def extended_gcd a, b
      x, old_x, y, old_y = 0, 1, 1, 0
      r, old_r = b.abs, a.abs
      while r != 0
         quotient = old_r / r
         old_r, r = r, old_r - quotient * r
         old_x, x = x, old_x - quotient * x
         old_y, y = y, old_y - quotient * y 
      end
      return old_r, old_x * (a < 0 ? -1 : 1)
   end 

   def mod_inverse a, b
      g, old_x = extended_gcd(a, b)
      return old_x % b
   end

   def generate_random_prime range_start, range_end
      prime = rand(range_start - range_end) + range_end;
      #check if its prime
      while !Prime.prime?(prime)
         prime % 2 ? prime += 1 : prime += 2
      end
      return prime
   end 

   def n
      #returns the value of 'n' passed in the initialize
      return @n
   end

   def e
      #returns the value of 'e' passed in the initialize
      return @e
   end

   def d
      #returns the value of 'd' passed in the initialize
      return @d
   end

   def new_key
      #generates a new 'n','e' and 'd' values following the RSA algorithm. Returns a new array of three elements where the first element is 'n', the second is 'e' and the third is 'd'. Each time it is called a new key must be returned.
      prime_range_start = rand(1000) # some magic numbers but it can be added in hte initilizer
      prime_range_end = prime_range_start + 1000
      
      prime_p = generate_random_prime(prime_range_start, prime_range_end)
      prime_q = generate_random_prime(prime_range_start, prime_range_end)

      n = prime_q * prime_p
      lambda_n = (prime_q - 1).lcm(prime_p - 1)
      e = 3
      while lambda_n.gcd(e) != 1
         e += 1
      end
      d = mod_inverse(e, lambda_n)
      return_values = [n, e, d]
      return return_values
   end

   def encrypt message
      #encrypts the message passed. The message is of type string. Encrypts each symbol of this string by using its ASCII number representation and returns the encrypted message.
      return (message.chars.map {|ch| pow_mod(ch.ord, @e, @n)}).join(".")
   end

   def decrypt message
      #decrypts the message passed. The message is of type string. Decrypts each symbol of this string Encrypts each symbol of this string by using its ASCII number representationand returns the decrypted message. 
      return (message.split(".").map {|ch| (pow_mod(ch.to_i, @d, @n)).chr}).join("")
   end 
end
