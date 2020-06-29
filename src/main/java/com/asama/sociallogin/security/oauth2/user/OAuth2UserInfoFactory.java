package com.asama.sociallogin.security.oauth2.user;

import java.util.Map;

import com.asama.sociallogin.exception.OAuth2AuthenticationProcessingException;
import com.asama.sociallogin.model.AuthProvider;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(AuthProvider.facebook.toString())) {
            return new FacebookOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(AuthProvider.github.toString())) {
            return new GithubOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException("Sorry! Login with "+ registrationId + " is not supported yet.");
        }
    }
}
