package boot.security.auth0;

import java.security.Principal;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class EchoController {

	@GetMapping("/ping")
	public String ping() {
		return "pong";
	}
	
	@GetMapping("/greeting")
	public OidcUser greeting(Principal principal) {
		log.info("Principal class:{0}",principal.getClass());
		OAuth2AuthenticationToken token = (OAuth2AuthenticationToken)principal;
		log.info("Authentication.getDetails class:{0}",token.getClass());
		WebAuthenticationDetails details = (WebAuthenticationDetails)token.getDetails();
		log.info("Authentication.getPrincipal class:{0}",details.getClass());
		OidcUser oidcuser = (OidcUser)token.getPrincipal();
		return oidcuser;
	}
	
	/*
	 * The Authentication instance in SecurityContext is the same object of java.security.principal 
	 */
	@GetMapping("/greeting2")
	public OidcUser greeting() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		log.info("Authentication class:{0}",auth.getClass());
		OAuth2AuthenticationToken token = (OAuth2AuthenticationToken)auth;
		log.info("Authentication.getDetails class:{0}",auth.getClass());
		WebAuthenticationDetails details = (WebAuthenticationDetails)auth.getDetails();
		log.info("Authentication.getPrincipal class:{0}",details.getClass());
		OidcUser oidcuser = (OidcUser)auth.getPrincipal();	
		return oidcuser;
	}
	
	/*
	 * The @AuthenticationPrincipal map Authentication.getPrincipal as the parameter of the MVC function
	 */
	@GetMapping("/greeting3")
	public OidcUser greeting(@AuthenticationPrincipal OidcUser oidcuser) {
		return oidcuser;
	}
}
