package com.jfwang.preauth_sm;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

@Configuration
@EnableWebSecurity
// @EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	/*
	 * @Autowired private OAuth2UserService<OidcUserRequest, OidcUser>
	 * oidcUserService;
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterAfter(siteminderFilter(), RequestHeaderAuthenticationFilter.class)
			.authorizeRequests()
			.antMatchers("/", "/Token").permitAll()
			.antMatchers("/admin/**").hasAuthority("ADMIN")
			.antMatchers("/user/**").hasAuthority("USER")
			.antMatchers("/both/**").hasAnyAuthority("USER", "ADMIN")
			.anyRequest().authenticated()
			.and()
			// for testing
	  		.formLogin().permitAll() 
	  		.and() 
	  		.logout().permitAll();
		    /* uncomment to use oauth2 
		    .oauth2Login().userInfoEndpoint();
			*/
	}

	
/*
 * Setup pre-authenticated header authorization
 * change with caution
 */
	@Bean(name = "siteminderFilter")
	public RequestHeaderAuthenticationFilter siteminderFilter() throws Exception {
		RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter = new RequestHeaderAuthenticationFilter();
		// for UBS it is x-auth-uids
		requestHeaderAuthenticationFilter.setPrincipalRequestHeader("SM_USER");
		// set to true if anomyous login is not allowed
		requestHeaderAuthenticationFilter.setExceptionIfHeaderMissing(false);
		requestHeaderAuthenticationFilter.setAuthenticationManager(authenticationManager());
		return requestHeaderAuthenticationFilter;
	}
	
	@Bean(name = "preAuthProvider")
	PreAuthenticatedAuthenticationProvider preauthAuthProvider() throws Exception {
		PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
		provider.setPreAuthenticatedUserDetailsService(userDetailsServiceWrapper());
		return provider;
	}
 

	@Bean
	UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> userDetailsServiceWrapper() throws Exception {
		UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> wrapper = new UserDetailsByNameServiceWrapper<>();
		wrapper.setUserDetailsService(new CustomUserDetailsService());
		return wrapper;
	}


	/* 
	 * uncomment for local testing
	 */

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("user").password("{noop}user").authorities("USER")
			.and()
			.withUser("admin").password("{noop}admin").authorities("ADMIN");
	}

}