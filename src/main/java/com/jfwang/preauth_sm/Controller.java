package com.jfwang.preauth_sm;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/*
 * Sample URLs for testing different roles/authorities
 */

@RestController
public class Controller {

	   @GetMapping("/")
	   public String main() {
	      return "Main Page, not protected.";
	   }

	   @GetMapping("/both")
	   public String Test() {
	      return "Allow Both Admin and User Roles";
	   }

	   @GetMapping("/user")
	   public String groupOne() {
	      return "Hello Users!";
	   }

	   @GetMapping("/admin")
	   public String groupTwo() {
	      return "Hello Admins";
	   }

	   @GetMapping("/Token")
	   public String token() {
		   Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		   return auth.toString();
	   }
	}
