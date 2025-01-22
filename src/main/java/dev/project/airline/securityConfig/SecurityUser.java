package dev.project.airline.securityConfig;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.boot.autoconfigure.task.TaskExecutionProperties.Simple;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import dev.project.airline.roles.Role;
import dev.project.airline.user.User;

public class SecurityUser implements UserDetails{

    private User user;
    
    public SecurityUser(User user) {
        this.user = user;
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        
         Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
           
         for (Role rol : user.getRoles()) {
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(rol.getName());
            authorities.add(authority);
         }
            return authorities;
    }
}
