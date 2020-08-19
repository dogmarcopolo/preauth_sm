package com.jfwang.preauth_sm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/*
 * change this implementation to get user information from database, LDAP, etc
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {


	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		/*
		 * TODO
		 */
		if (username == null) username = "anonymous";
		Collection<GrantedAuthority> authorities = new ArrayList<>();		
 	   	authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
		UserDetails details = new User(username, "", authorities);
		return details;	
	}

}
