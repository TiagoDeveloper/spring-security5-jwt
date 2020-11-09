package com.tiagodeveloper;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.util.ResourceUtils;

@SpringBootApplication
public class SpringSecurity5JwtApplication {
	
//	    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, URISyntaxException {
//	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//	        keyGen.initialize(2048);
//	        KeyPair keypair = keyGen.generateKeyPair();
//	        PrivateKey privateKey = keypair.getPrivate();
//	        PublicKey publicKey = keypair.getPublic();
//	        System.out.println("-----BEGIN PRIVATE KEY-----");
//	        System.out.println(Base64.getMimeEncoder().encodeToString(privateKey.getEncoded()));
//	        System.out.println("-----END PRIVATE KEY-----");
//	        System.out.println();
//	        System.out.println();
//	        System.out.println("-----BEGIN PUBLIC KEY-----");
//	        System.out.println(Base64.getMimeEncoder().encodeToString(publicKey.getEncoded()));
//	        System.out.println("-----END PUBLIC KEY-----");
//	
////			 File f1 = ResourceUtils.getFile("classpath:paraeditar.key");
////			 FileWriter writer = new FileWriter(f1);
////			 writer.write("Deu certo");
////			 
////			 writer.close();
////			 System.out.println(f1);
//	    }

	public static void main(String[] args) throws IOException {
		SpringApplication.run(SpringSecurity5JwtApplication.class, args);
	}
}
