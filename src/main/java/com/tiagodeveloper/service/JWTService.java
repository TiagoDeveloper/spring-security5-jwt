package com.tiagodeveloper.service;

import org.springframework.security.core.Authentication;

public interface JWTService {
	
	public String generatedToken(Authentication authentication);

}
