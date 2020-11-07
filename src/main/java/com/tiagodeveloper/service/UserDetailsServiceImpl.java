package com.tiagodeveloper.service;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		List<String> rolesList = Arrays.asList("GUEST","AUTHENTICATED");
		
		String[] authorities = Arrays.copyOf(rolesList.toArray(), rolesList.size(), String[].class);
		
		return User.builder()
				.username("tiago")
				.password(new BCryptPasswordEncoder().encode("pass"))
				.authorities(authorities)
				.build();
	}

}
