package com.tiagodeveloper;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringSecurity5JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurity5JwtApplication.class, args);
	}
//	
//	public static PublicKey bigIntegerToPublicKey(BigInteger e, BigInteger m) throws NoSuchAlgorithmException, InvalidKeySpecException  {
//	    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
//	    KeyFactory fact = KeyFactory.getInstance("RSA");
//	    PublicKey pubKey = fact.generatePublic(keySpec);
//	    return pubKey;
//	}
//
//	public static PrivateKey bigIntegerToPrivateKey(BigInteger e, BigInteger m) throws NoSuchAlgorithmException, InvalidKeySpecException {
//	    RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
//	    KeyFactory fact = KeyFactory.getInstance("RSA");
//	    PrivateKey privKey = fact.generatePrivate(keySpec);
//	    return privKey;
//	}

}
