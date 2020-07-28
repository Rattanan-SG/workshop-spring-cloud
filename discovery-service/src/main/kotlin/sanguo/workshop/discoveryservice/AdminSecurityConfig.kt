package sanguo.workshop.discoveryservice

import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy

@Configuration
class AdminSecurityConfig : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.NEVER).and()
            .authorizeRequests()
            .antMatchers(HttpMethod.GET, "/").hasRole("ADMIN")
            .antMatchers("/info", "/health").authenticated()
            .anyRequest().denyAll().and()
            .httpBasic().disable()
            .csrf().disable()
    }
}