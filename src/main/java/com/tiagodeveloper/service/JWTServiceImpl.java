package com.tiagodeveloper.service;

import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Service
public class JWTServiceImpl implements JWTService {
	
	@Value("${jwt.private.key}")
	private RSAPrivateKey privateKey;
	
	@Override
	public String generatedToken(Authentication authentication) {
		
		Instant now = Instant.now();
		long expiry = 36000L;

		String scope = authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(" "));
		JWTClaimsSet claims = new JWTClaimsSet.Builder()
				.issuer("self")
				.issueTime(new Date(now.toEpochMilli()))
				.expirationTime(new Date(now.plusSeconds(expiry).toEpochMilli()))
				.subject(authentication.getName())
				.claim("scope", scope)
				.build();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
		
		SignedJWT jwt = new SignedJWT(header, claims);
		
		return sign(jwt).serialize();
	}
	private SignedJWT sign(SignedJWT jwt) {
		try {
			jwt.sign(new RSASSASigner(this.privateKey));
			return jwt;
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}
}
