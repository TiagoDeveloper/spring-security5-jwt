package com.tiagodeveloper.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tiagodeveloper.service.JWTService;

@RestController
@RequestMapping("/login")
public class LoginController {
	
	@Autowired
	private JWTService jwtService;
	
	@PostMapping
	public ResponseEntity<String> login(Authentication authentication) {
		return new ResponseEntity<String>(this.jwtService.generatedToken(authentication), HttpStatus.OK);
	}

}
