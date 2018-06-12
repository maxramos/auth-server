package com.maxaramos.authserver.controller.ui;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MainController {

	@GetMapping("/")
	public String index(Model model, Authentication authentication) {
		model.addAttribute("username", authentication.getName());
		return "index";
	}

}
