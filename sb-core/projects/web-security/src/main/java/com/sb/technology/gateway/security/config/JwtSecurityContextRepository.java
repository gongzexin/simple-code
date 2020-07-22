package com.sb.technology.gateway.security.config;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sb.technology.gateway.utils.JWTUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class JwtSecurityContextRepository implements SecurityContextRepository {

    protected final Log logger = LogFactory.getLog(this.getClass());

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        String tokenString = "";
        Cookie[] cookies = request.getCookies();
        if (cookies != null){
            for (Cookie cookie : cookies){
                if (JWTUtil.AUTHENTICATION_COOKIE_NAME.equals(cookie.getName()))   tokenString = cookie.getValue();
            }
            if (tokenString == null || tokenString.isEmpty())   return this.generateNewContext();
            try {
                DecodedJWT decodedJWT = JWTUtil.decodeToken(tokenString);
                Map<String, Claim> claims = decodedJWT.getClaims();
                String principal = claims.get("principal").asString();
                String roles = claims.get("authorities").asString();
                Collection<GrantedAuthority> authorities = new ArrayList<>();
                for (String role : roles.split(",")){
                    GrantedAuthority authority = new SimpleGrantedAuthority(role.trim());
                    authorities.add(authority);
                }
                UserDetails userDetails = new User(principal, "", authorities);
                Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContext securityContext = new SecurityContextImpl(authentication);
                return securityContext;
            }catch (JWTVerificationException e){
                if (this.logger.isDebugEnabled()) {
                    this.logger.debug("无效的认证信息");
                }
            }
        }
        return this.generateNewContext();
    }

    @Override
    public void saveContext(SecurityContext securityContext, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {

    }

    @Override
    public boolean containsContext(HttpServletRequest httpServletRequest) {
        return false;
    }

    protected SecurityContext generateNewContext() {
        return SecurityContextHolder.createEmptyContext();
    }
}
