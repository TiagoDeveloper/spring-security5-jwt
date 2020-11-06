package com.tiagodeveloper.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login")
public class LoginController {
	
	@PostMapping
	public ResponseEntity<Void> login(Authentication authentication) {
		System.out.println(authentication);
		return new ResponseEntity<Void>(HttpStatus.OK);
	}

}
