package fi.haagahelia.course;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig  {

	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests().requestMatchers("/", "/home").permitAll()
		.and()
			.authorizeHttpRequests().anyRequest().authenticated()
		.and()
			.formLogin()
			.loginPage("/login")
			.permitAll()
		.and()
			.logout().permitAll();
				
		return http.build();
	}

	/*
	 * protected void configure(AuthenticationManagerBuilder auth) throws Exception
	 * { auth.inMemoryAuthentication() .passwordEncoder(passwordEncoder())
	 * .withUser("user") .password(passwordEncoder().encode("userPass"))
	 * .roles("USER");
	 * 
	 * auth.inMemoryAuthentication() .passwordEncoder(passwordEncoder())
	 * .withUser("admin") .password(passwordEncoder().encode("adminPass"))
	 * .roles("USER", "ADMIN"); }
	 * 
	 * @Bean public PasswordEncoder passwordEncoder() { return new
	 * BCryptPasswordEncoder(); }
	 */
  
  
}