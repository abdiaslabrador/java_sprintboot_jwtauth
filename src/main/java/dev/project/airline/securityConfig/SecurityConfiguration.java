package dev.project.airline.securityConfig;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import static org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagers.hasScope;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Value("${JWT_SECRET_KEY}")
    private String key;

    private String base_url = "/api/v1";

    private JpaUserDetailsService jpaUserDetailsService;

    public SecurityConfiguration(JpaUserDetailsService userDetailsService) {
            this.jpaUserDetailsService = userDetailsService;
    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(new ImmutableSecret<>(key.getBytes()));
    }
    
    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] bytes = key.getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(bytes, 0, bytes.length, "RSA");
        return NimbusJwtDecoder.withSecretKey(secretKey).macAlgorithm(MacAlgorithm.HS512).build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

            http
                            .cors(cors -> cors.configurationSource(corsConfiguration()))
                            .csrf(csrf -> csrf.disable())
                            .formLogin(form -> form.disable())
                            .authorizeHttpRequests(auth -> auth
                                            .requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll()
                                            .requestMatchers(base_url + "/login").hasAnyRole("USER", "ADMIN")// principio de mínimos
                                            .requestMatchers(HttpMethod.POST, base_url + "/auth/token").hasAnyRole("USER", "ADMIN")// principio de mínimos
                                            .requestMatchers(base_url + "/private").access(hasScope("READ"))
                                            .requestMatchers(base_url).permitAll() 
                                            .requestMatchers(base_url + "/users").permitAll()
                                            // .anyRequest().access(hasScope("READ"))
                                            .anyRequest().authenticated()
                                            )
                            .userDetailsService(jpaUserDetailsService)
                            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                            .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.decoder(jwtDecoder())))
                            .httpBasic(withDefaults());

            http.headers(header -> header.frameOptions(frame -> frame.sameOrigin()));

            return http.build();

    }

   @Bean
    CorsConfigurationSource corsConfiguration() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5173"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // @Bean  // <--- esto es para probar sin base de datos
    // UserDetailsService userDetailsService() {
    //     return new InMemoryUserDetailsManager(
    //             User.withUsername("abdias")
    //             .password("{noop}password")
    //             .authorities("READ", "ROLE_USER")
    //             .build());
    // }
}
