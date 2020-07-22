package com.sb.technology.gateway;

import com.sb.technology.gateway.utils.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class PasswordEncode {



    public static void main(String[] args) {
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("admin"));
        authorities.add(new SimpleGrantedAuthority("dba"));

        UserDetails userDetails = new User("username", "encodepassword", authorities);

        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails,"password", authorities);

        String token = JWTUtil.encodeToken(authentication);
        System.out.println(token);
    }
}
