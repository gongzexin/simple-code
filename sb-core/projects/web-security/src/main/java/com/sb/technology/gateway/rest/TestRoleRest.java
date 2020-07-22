package com.sb.technology.gateway.rest;

import com.alibaba.fastjson.JSON;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;


@RestController
public class TestRoleRest {

    @GetMapping("/role/getUserDetails")
    public String adminTest(){
        return JSON.toJSONString(SecurityContextHolder.getContext().getAuthentication().getPrincipal());
    }

    @GetMapping("/business/getUserDetails")
    public String userTest(){
        return JSON.toJSONString(SecurityContextHolder.getContext().getAuthentication().getPrincipal());
    }

    @GetMapping("/webSecurity")
    public String webSecurity(){
        return "webSecurity";
    }

    @GetMapping("/oauth2")
    public String oauth2(){
        return JSON.toJSONString(SecurityContextHolder.getContext().getAuthentication());
    }

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("/login")
    public ModelAndView login(ModelAndView modelAndView){
        modelAndView.setViewName("/login/login");
        return modelAndView;
    }
}
