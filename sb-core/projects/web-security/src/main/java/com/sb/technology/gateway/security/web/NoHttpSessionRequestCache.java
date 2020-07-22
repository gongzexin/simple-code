package com.sb.technology.gateway.security.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.TreeMap;

public class NoHttpSessionRequestCache implements RequestCache {

    protected final static Log logger = LogFactory.getLog(NoHttpSessionRequestCache.class.getClass());
    private RequestMatcher requestMatcher;
    private PortResolver portResolver = new PortResolverImpl();
    private static Map<String, SavedRequest> savedRequestCache = new TreeMap<>();
    public static final String REQUEST_PARAM_KEY="savedRequest";

    public NoHttpSessionRequestCache(){
        requestMatcher = AnyRequestMatcher.INSTANCE;
    }

    @Override
    public void saveRequest(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        if (this.requestMatcher.matches(httpServletRequest)) {
            DefaultSavedRequest savedRequest = new DefaultSavedRequest(httpServletRequest, this.portResolver);
            savedRequestCache.put(String.valueOf(Thread.currentThread().getId()), savedRequest);
            this.logger.debug("DefaultSavedRequest added to " + savedRequest);
        } else {
            this.logger.debug("Request not saved as configured RequestMatcher did not match");
        }
    }

    @Override
    public SavedRequest getRequest(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        String savedRequestID = httpServletRequest.getParameter(REQUEST_PARAM_KEY);
        if (savedRequestID != null && !savedRequestID.isEmpty() && savedRequestCache.containsKey(savedRequestID))   return savedRequestCache.get(savedRequestID);
        else   return null;
    }

    @Override
    public HttpServletRequest getMatchingRequest(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        SavedRequest saved = this.getRequest(httpServletRequest, httpServletResponse);
        if (!this.matchesSavedRequest(httpServletRequest, saved)) {
            this.logger.debug("saved request doesn't match");
            return null;
        } else {
            this.removeRequest(httpServletRequest, httpServletResponse);
            return httpServletRequest;
        }
    }

    private boolean matchesSavedRequest(HttpServletRequest request, SavedRequest savedRequest){
        if (savedRequest == null)   return false;
        String savedRequestID = request.getParameter(REQUEST_PARAM_KEY);
        if (savedRequestID == null || savedRequestID.isEmpty())   return false;
        return savedRequest.getRedirectUrl().startsWith(request.getRequestURI());
    }

    @Override
    public void removeRequest(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        String savedRequestID = httpServletRequest.getParameter(REQUEST_PARAM_KEY);
        if (savedRequestID == null || savedRequestID.isEmpty()){
            savedRequestCache.remove(savedRequestID);
        }
    }
}
