package com.sb.technology.gateway.security.config;

import com.alibaba.fastjson.JSON;
import com.sb.technology.gateway.security.web.NoHttpSessionRequestCache;
import com.sb.technology.gateway.utils.JWTUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.http.Cookie;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${server.servlet.context-path}")
    private String CONTENT_PATH;
    private static RequestCache noHttpSessionRequestCache = new NoHttpSessionRequestCache();
    private static final String LOGIN_PAGE="/login";

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetailsService userDetailsService = username -> {
            List<SimpleGrantedAuthority> roles = new ArrayList<>();
            roles.add(new SimpleGrantedAuthority("ROLE_admin"));
            User user = new User(username, "$2a$10$BHqUXG6GkVJPE3JppY/pKOaK1U7ozGr8Q.EJDDxw2Pmb/CWD83f8y", true, true, true, true, roles);
            return user;
        };
        return userDetailsService;
    }

    @Bean
    public RequestCache noHttpSessionRequestCache(){
        return noHttpSessionRequestCache;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                .requestCache()
                    .requestCache(noHttpSessionRequestCache)
                    .and()
                .securityContext()
                    .securityContextRepository(new JwtSecurityContextRepository())
                    .and()
                .authorizeRequests()
                    .antMatchers("/login/**").permitAll()
                    .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .loginPage(LOGIN_PAGE)
                    .successHandler(
                            (req, resp, authentication) -> {
                                String token = JWTUtil.encodeToken(authentication);
                                resp.addCookie(new Cookie(JWTUtil.AUTHENTICATION_COOKIE_NAME, token));

                                SavedRequest savedRequest = noHttpSessionRequestCache.getRequest(req, resp);
                                if (savedRequest != null){
                                    String targetUrl = savedRequest.getRedirectUrl();
                                    if (targetUrl.indexOf("?") != -1)   targetUrl+="&";
                                    targetUrl += NoHttpSessionRequestCache.REQUEST_PARAM_KEY + req.getParameter(NoHttpSessionRequestCache.REQUEST_PARAM_KEY);
                                    resp.sendRedirect(targetUrl);
                                }else {
                                    Object principal = authentication.getPrincipal();
                                    resp.setContentType("application/json;charset=utf-8");
                                    Map<String, Object> successInfo = new HashMap<>();
                                    successInfo.put("success", "true");
                                    successInfo.put("principal", principal);
                                    resp.getWriter().write(JSON.toJSONString(successInfo));
                                }
                            }
                    )
                    .failureHandler(
                            (req, resp, authenticationException) -> {
                                resp.setContentType("application/json;charset=utf-8");
                                Map<String, Object> failureInfo = new HashMap<>();
                                failureInfo.put("success", false);
                                if (authenticationException instanceof BadCredentialsException){
                                    failureInfo.put("msg", "用户名或密码错误！");
                                }else if (authenticationException instanceof DisabledException){
                                    failureInfo.put("msg", "账户被禁用，请联系管理员！");
                                }else if (authenticationException instanceof LockedException){
                                    failureInfo.put("msg", "账户被锁定，请联系管理员！");
                                }else if (authenticationException instanceof AccountExpiredException){
                                    failureInfo.put("msg", "账户已过期，请联系管理员！");
                                }else if (authenticationException instanceof CredentialsExpiredException){
                                    failureInfo.put("msg", "密码过期，请联系管理员！");
                                }
                                resp.getWriter().write(JSON.toJSONString(failureInfo));
                            }
                    )
                    .and()
                .exceptionHandling()
                    .authenticationEntryPoint(
                            (req, resp, authenticationException) -> {
                                String requestUrl = req.getRequestURI();
                                if (requestUrl.equals(CONTENT_PATH + "/oauth/authorize") && "code".equals(req.getParameter("response_type"))){
                                    resp.sendRedirect(CONTENT_PATH + LOGIN_PAGE + "?" + NoHttpSessionRequestCache.REQUEST_PARAM_KEY + "=" + Thread.currentThread().getId());
                                }else {
                                    Map<String, Object> failureInfo = new HashMap<>();
                                    failureInfo.put("err", "unauthorized");
                                    failureInfo.put("error_description", authenticationException.getMessage());
                                    resp.setContentType("application/json;charset=utf-8");
                                    resp.getWriter().write(JSON.toJSONString(failureInfo));
                                }
                            }
                    )
                    .and()
                .csrf()
                    .disable();
    }
}
