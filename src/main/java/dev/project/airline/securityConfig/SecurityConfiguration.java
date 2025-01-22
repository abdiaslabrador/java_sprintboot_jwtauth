package dev.project.airline.securityConfig;
import static org.springframework.security.config.Customizer.withDefaults;

import java.util.ArrayList;
import java.util.Collection;

import dev.project.airline.securityConfig.JpaUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    private String base_url = "/api/v1";

    private JpaUserDetailsService jpaUserDetailsService;

    public SecurityConfiguration(JpaUserDetailsService jpaUserDetailsService) {
        this.jpaUserDetailsService = jpaUserDetailsService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(withDefaults())
            .csrf(csrf -> csrf.disable())
            .formLogin(form -> form.disable())
            .logout(out -> out
                            .logoutUrl("/api/v1/logout")
                            .invalidateHttpSession(true)
                            .deleteCookies("JSESSIONID"))
            .authorizeHttpRequests( auth -> auth
            .requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**"))
            .permitAll()
            .requestMatchers(base_url + "/login").hasAnyRole("USER", "ADMIN")
                .requestMatchers(base_url + "/airport").permitAll()
                .requestMatchers( base_url + "/public").permitAll()
                .requestMatchers(HttpMethod.GET, base_url + "/private").hasRole("USER")
                .anyRequest().authenticated())
            .userDetailsService(jpaUserDetailsService)
            .httpBasic(withDefaults())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));

        http.headers(header -> header.frameOptions(frame -> frame.sameOrigin()));

        return http.build();

    }

    // @Bean
    // PasswordEncoder passwordEncoder(){
    //     return new BCryptPasswordEncoder();
    // }

    // @Bean 
    // public InMemoryUserDetailsManager userDetailsManager(){
    //     UserDetails user = User.builder()
    //             .username("abdias")
    //             .password("{noop}1234")
    //             .roles("USER")
    //             .build();
        
    //     UserDetails user2 = User.builder()
    //     .username("daniel")
    //     .password("{noop}1234")
    //     .roles("ADMIN")
    //     .build();

    //     Collection<UserDetails> users = new ArrayList<>();
    //     users.add(user);
    //     users.add(user2);

    //     return new InMemoryUserDetailsManager(users);
    // }
}
