package boot.security.auth0;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.debug(true);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		  .authorizeRequests()
		    .antMatchers("/greeting**")
		      .authenticated()
		    .anyRequest()
		      .permitAll()
		  .and()
		    .oauth2Login(oauth2 -> {
		    });
	}
	
	@Bean
	public UserDetailsService defaultUserDetailService() throws Exception {
		UserDetailsService service = this.userDetailsServiceBean();
		return service;
	}

}
