package com.tiagodeveloper.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tiagodeveloper.dto.UsuarioDTO;

@RestController
@RequestMapping("/home")
public class HomeController {

	@PreAuthorize("hasAnyRole('ROLE_GUEST')")
	@GetMapping
	public ResponseEntity<UsuarioDTO> home() {
		return new ResponseEntity<UsuarioDTO>(UsuarioDTO.builder()
				.username("tiago")
				.password("123456")
				.build(), HttpStatus.OK);
	}
	
}
