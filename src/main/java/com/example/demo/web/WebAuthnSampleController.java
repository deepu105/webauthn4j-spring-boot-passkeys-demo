/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.demo.web;

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidationResponse;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorImpl;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.exception.PrincipalNotFoundException;
import com.webauthn4j.springframework.security.exception.WebAuthnAuthenticationException;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.UUIDUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Login controller
 */
@SuppressWarnings("SameReturnValue")
@Controller
public class WebAuthnSampleController {

    private final Log logger = LogFactory.getLog(getClass());

    private static final String REDIRECT_LOGIN = "redirect:/login";

    private static final String VIEW_SIGNUP = "signup";

    private static final String VIEW_HOME = "home";

    private static final String VIEW_LOGIN = "login";

    @Autowired
    private WebAuthnAuthenticatorManager webAuthnAuthenticatorManager;

    @Autowired
    private WebAuthnRegistrationRequestValidator registrationRequestValidator;

    @Autowired
    private ChallengeRepository challengeRepository;

    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    @ModelAttribute
    public void addAttributes(Model model, HttpServletRequest request) {
        Challenge challenge = challengeRepository.loadOrGenerateChallenge(request);
        model.addAttribute("webAuthnChallenge", Base64UrlUtil.encodeToString(challenge.getValue()));
        model.addAttribute("webAuthnCredentialIds", getCredentialIds());
    }

    @GetMapping(value = "/")
    public String index(Model model) {
        var details = SecurityContextHolder.getContext().getAuthentication().getDetails();
        model.addAttribute("details", details);
        return VIEW_HOME;
    }

    @GetMapping(value = "/login")
    public String login() {
        return VIEW_LOGIN;
    }

    @GetMapping(value = "/signup")
    public String template(Model model) {
        UserCreateForm userCreateForm = new UserCreateForm();
        String userHandle = Base64UrlUtil.encodeToString(UUIDUtil.convertUUIDToBytes(UUID.randomUUID()));
        userCreateForm.setUserHandle(userHandle);
        model.addAttribute("userForm", userCreateForm);
        return VIEW_SIGNUP;
    }

    @PostMapping(value = "/signup")
    public String create(HttpServletRequest request, @Valid @ModelAttribute("userForm") UserCreateForm userCreateForm, BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        try {
            if (result.hasErrors()) {
                model.addAttribute("errorMessage", "Your input needs correction.");
                logger.error("User input validation failed.");

                return VIEW_SIGNUP;
            }

            WebAuthnRegistrationRequestValidationResponse registrationRequestValidationResponse;
            try {
                registrationRequestValidationResponse = registrationRequestValidator.validate(
                    request,
                    userCreateForm.getClientDataJSON(),
                    userCreateForm.getAttestationObject(),
                    userCreateForm.getTransports(),
                    userCreateForm.getClientExtensions()
                );
            } catch (WebAuthnException | WebAuthnAuthenticationException e) {
                model.addAttribute("errorMessage", "Authenticator registration request validation failed. Please try again.");
                logger.error("WebAuthn registration request validation failed.", e);
                return VIEW_SIGNUP;
            }

            String username = userCreateForm.getUsername();

            WebAuthnAuthenticator authenticator = new WebAuthnAuthenticatorImpl(
                "authenticator",
                username,
                registrationRequestValidationResponse.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
                registrationRequestValidationResponse.getAttestationObject().getAttestationStatement(),
                registrationRequestValidationResponse.getAttestationObject().getAuthenticatorData().getSignCount(),
                registrationRequestValidationResponse.getTransports(),
                registrationRequestValidationResponse.getRegistrationExtensionsClientOutputs(),
                registrationRequestValidationResponse.getAttestationObject().getAuthenticatorData().getExtensions()
            );

            try {
                webAuthnAuthenticatorManager.createAuthenticator(authenticator);
            } catch (IllegalArgumentException ex) {
                model.addAttribute("errorMessage", "Registration failed. The user may already be registered.");
                logger.error("Registration failed.", ex);
                return VIEW_SIGNUP;
            }
        } catch (RuntimeException ex) {
            model.addAttribute("errorMessage", "Registration failed by unexpected error.");
            logger.error("Registration failed.", ex);
            return VIEW_SIGNUP;
        }

        redirectAttributes.addFlashAttribute("successMessage", "User registration successful. Please login.");
        return REDIRECT_LOGIN;
    }

    private List<String> getCredentialIds() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        if (principal == null || authenticationTrustResolver.isAnonymous(authentication)) {
            return Collections.emptyList();
        } else {
            try {
                List<WebAuthnAuthenticator> webAuthnAuthenticators = webAuthnAuthenticatorManager.loadAuthenticatorsByUserPrincipal(principal);
                return webAuthnAuthenticators.stream()
                    .map(webAuthnAuthenticator -> Base64UrlUtil.encodeToString(webAuthnAuthenticator.getAttestedCredentialData().getCredentialId()))
                    .collect(Collectors.toList());
            } catch (PrincipalNotFoundException e) {
                return Collections.emptyList();
            }
        }
    }

}
