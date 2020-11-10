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

	@PreAuthorize("hasAnyAuthority('ROLE_GUEST')")
	@GetMapping("/guest")
	public ResponseEntity<UsuarioDTO> home() {
		return new ResponseEntity<UsuarioDTO>(UsuarioDTO.builder()
				.username("tiago")
				.password("123456")
				.build(), HttpStatus.OK);
	}
	
	@PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
	@GetMapping("/admin")
	public ResponseEntity<UsuarioDTO> home2() {
		return new ResponseEntity<UsuarioDTO>(UsuarioDTO.builder()
				.username("admin")
				.password("123456")
				.build(), HttpStatus.OK);
	}
	
}
