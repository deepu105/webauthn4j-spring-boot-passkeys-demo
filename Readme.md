# Passkeys with Spring Boot and WebAuthn4j

This is a bare-bones Spring Boot web application with [WebAuthn4j](https://github.com/webauthn4j/webauthn4j-spring-security) to demonstrate passkeys with WebAuthn.

The user details are stored in memory.

## Why use passkeys?

Passkeys are FIDO credentials that are discoverable by browsers or housed in hardware authenticators like your mobile device, laptop, or security keys for passwordless authentication. Passkeys replace passwords with cryptographic key pairs for phishing-resistant sign-in security and an improved user experience. The cryptographic keys are used from end-user devices (computers, phones, or security keys) for user authentication. Any passwordless FIDO credential is a passkey.

We believe that passkeys offer a viable alternative to passwords for consumer applications, and we are committed to promoting this much-needed industry shift by making it easy for you, developers, and builders to offer that experience to your users.

## Clone and run the application

Start by cloning the application.

```shell
git clone https://github.com/deepu105/webauthn4j-spring-boot-passkeys-demo.git

cd webauthn4j-spring-boot-passkeys-demo
./gradlew bootRun
```

Visit [http://localhost:8080/](http://localhost:8080/). You should see the below screen. Try registering a new user with passkeys and log in.

![Sign up Screen](https://images.ctfassets.net/23aumh6u8s0i/6AMgTTV5zvVh1kqb3Y3MjQ/ad84606693d09195dc43a4aa1c5ea8a5/register-screen-webauthn4j.jpg)

### WebAuthn4j configuration

Let's look at some of the important parts of the application.

The `webauthn4j-spring-security-core` dependency, in `build.gradle` file, provides the Spring Security integration for WebAuthn4j.

The required beans for WebAuthn4j are configured in `src/main/java/com/example/demo/config/WebSecurityBeanConfig.java`. The `InMemoryWebAuthnAuthenticatorManager` is used to keep things simple but it means authenticator data is lost on application restart. For production use, it is better to implement the `WebAuthnAuthenticatorManager` interface and persist credential IDs for users.

WebAuthn4j is configured using the standard Spring Security filter chain in `src/main/java/com/example/demo/config/WebSecurityConfig.java`.

<details>
  <summary>**WebSecurityConfig.java**</summary>
```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    private final Log logger = LogFactory.getLog(getClass());
    @Autowired
    private ApplicationContext applicationContext;
    @Bean
    public WebAuthnAuthenticationProvider webAuthnAuthenticationProvider(WebAuthnAuthenticatorService authenticatorService, WebAuthnManager webAuthnManager) {
        return new WebAuthnAuthenticationProvider(authenticatorService, webAuthnManager);
    }
    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers) {
        return new ProviderManager(providers);
    }
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            // ignore static resources
            web.ignoring().requestMatchers(
                "/favicon.ico",
                "/js/**",
                "/css/**",
                "/webjars/**");
        };
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        // WebAuthn Login
        http.apply(WebAuthnLoginConfigurer.webAuthnLogin())
            .defaultSuccessUrl("/", true)
            .failureHandler((request, response, exception) -> {
                logger.error("Login error", exception);
                response.sendRedirect("/login?error=Login failed: " + exception.getMessage());
            })
            .attestationOptionsEndpoint()
            .rp()
            .name("WebAuthn4J Passkeys Demo")
            .and()
            .pubKeyCredParams(
                // supported algorithms for cryptography
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
            )
            .attestation(AttestationConveyancePreference.DIRECT)
            .extensions()
            .uvm(true)
            .credProps(true)
            .extensionProviders()
            .and()
            .assertionOptionsEndpoint()
            .extensions()
            .extensionProviders();

        http.headers(headers -> {
            // 'publickey-credentials-get *' allows getting WebAuthn credentials to all nested browsing contexts (iframes) regardless of their origin.
            headers.permissionsPolicy(config -> config.policy("publickey-credentials-get *"));
            // Disable "X-Frame-Options" to allow cross-origin iframe access
            headers.frameOptions(Customizer.withDefaults()).disable();
        });

        // Authorization
        http.authorizeHttpRequests(authz -> authz
            .requestMatchers(HttpMethod.GET, "/login").permitAll()
            .requestMatchers(HttpMethod.POST, "/signup").permitAll()
            .anyRequest().access(getWebExpressionAuthorizationManager("@webAuthnSecurityExpression.isWebAuthnAuthenticated(authentication)"))
        );

        http.exceptionHandling(eh -> eh.accessDeniedHandler((request, response, accessDeniedException) -> {
            logger.error("Access denied", accessDeniedException);
            response.sendRedirect("/login");
        }));

        http.authenticationManager(authenticationManager);

        // As WebAuthn has its own CSRF protection mechanism (challenge), CSRF token is disabled here
        http.csrf(csrf -> {
            csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
            csrf.ignoringRequestMatchers("/webauthn/**");
        });

        return http.build();
    }
    private WebExpressionAuthorizationManager getWebExpressionAuthorizationManager(final String expression) {
        var expressionHandler = new DefaultHttpSecurityExpressionHandler();
        expressionHandler.setApplicationContext(applicationContext);
        var authorizationManager = new WebExpressionAuthorizationManager(expression);
        authorizationManager.setExpressionHandler(expressionHandler);
        return authorizationManager;
    }
}
```
</details>

The endpoints are configured in `src/main/java/com/example/demo/web/WebAuthnSampleController.java`. The `/` and `/login` endpoints are quite simple and self-explanatory. The `/signup` endpoint handles the WebAuthn registration request using WebAuthn4j. The request is first validated using `WebAuthnRegistrationRequestValidator` and then the authenticator is created using `WebAuthnAuthenticatorManager`.

<details>
  <summary>**WebAuthnSampleController.java**</summary>
```java
@Controller
public class WebAuthnSampleController {
    private final Log logger = LogFactory.getLog(getClass());
    private static final String VIEW_HOME = "home";
    private static final String VIEW_LOGIN = "login";
    @Autowired
    private WebAuthnAuthenticatorManager webAuthnAuthenticatorManager;
    @Autowired
    private WebAuthnRegistrationRequestValidator registrationRequestValidator;
    @GetMapping(value = "/")
    public String index(Model model) {
        var user = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        model.addAttribute("user", user);
        return VIEW_HOME;
    }
    @GetMapping(value = "/login")
    public String template(Model model) {
        var userCreateForm = new UserCreateForm();
        var userHandle = Base64UrlUtil.encodeToString(UUIDUtil.convertUUIDToBytes(UUID.randomUUID()));
        userCreateForm.setUserHandle(userHandle);
        model.addAttribute("userForm", userCreateForm);
        return VIEW_LOGIN;
    }
    @PostMapping(value = "/signup")
    public String create(HttpServletRequest request, @Valid @ModelAttribute("userForm") UserCreateForm userCreateForm, BindingResult result, Model model, RedirectAttributes redirectAttributes) {
        try {
            if (result.hasErrors()) {
                model.addAttribute("errorMessage", "Your input needs correction.");
                logger.error("User input validation failed.");
                return VIEW_LOGIN;
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
                return VIEW_LOGIN;
            }
            var username = userCreateForm.getUsername();
            var authenticator = new WebAuthnAuthenticatorImpl(
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
                return VIEW_LOGIN;
            }
        } catch (RuntimeException ex) {
            model.addAttribute("errorMessage", "Registration failed by unexpected error.");
            logger.error("Registration failed.", ex);
            return VIEW_LOGIN;
        }
        model.addAttribute("successMessage", "User registration successful. Please login.");
        return VIEW_LOGIN;
    }
}
```

</details>

### Client-side configuration

The file `src/main/resources/templates/login.html` handles login and sign-up. The login button will invoke the `navigator.credentials.get()` API and the register button will invoke the `navigator.credentials.create()` API. The buttons submit the corresponding forms with the input data in them. All inputs except the `username` field are hidden as their data will be set using JavaScript.

WebAuthn4j exposes `/webauthn/attestation/options` endpoint in the application to fetch the registration options. Some of the option parameters need to be decoded from base64URL. The [base64url-arraybuffer](https://github.com/deepu105/base64url-arraybuffer) library is used for this. The options are then passed to the `navigator.credentials.create()` API. The response from the API is then updated to the form fields and submitted to the `/signup` endpoint.

<details>
  <summary>**login.html**</summary>
```js
document.getElementById("signup-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const userHandle = document.getElementById("userHandle").value;
    const username = document.getElementById("username").value;
    try {
        const optionsRes = await fetch("/webauthn/attestation/options");
        const options = await optionsRes.json();
        const publicKey = {
            ...options,
            challenge: base64url.decode(options.challenge, true),
            user: {
                id: base64url.decode(userHandle, true),
                name: username,
                displayName: username,
            },
            excludeCredentials: options.excludeCredentials.map((credential) => ({
                ...credential,
                id: base64url.decode(credential.id, true),
            })),
            authenticatorSelection: {
                requireResidentKey: true,
                userVerification: "discouraged",
            },
        };
        const credential = await navigator.credentials.create({ publicKey });
        document.getElementById("clientDataJSON").value = base64url.encode(credential.response.clientDataJSON);
        document.getElementById("attestationObject").value = base64url.encode(credential.response.attestationObject);
        document.getElementById("clientExtensions").value = JSON.stringify(credential.getClientExtensionResults());
        document.getElementById("signup-form").submit();
    } catch (error) {
        console.error("Error:%s, Message:%s", error.name, error.message);
    }
});
```
</details>

WebAuthn4j exposes `/webauthn/assertion/options` endpoint in the application to fetch the authentication options. Some of the option parameters need to be decoded from base64URL. The options are then passed to the `navigator.credentials.get()` API. The response from the API is then updated to the form fields and submitted to the `/login` endpoint.

<details>
  <summary>**login.html**</summary>
```js
document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
        const optionsRes = await fetch("/webauthn/assertion/options");
        const options = await optionsRes.json();
        const publicKey = {
            ...options,
            challenge: base64url.decode(options.challenge, true),
            userVerification: "preferred",
        };
        const credential = await navigator.credentials.get({ publicKey });
        document.getElementById("credentialId").value = credential.id;
        document.getElementById("loginClientDataJSON").value = base64url.encode(credential.response.clientDataJSON);
        document.getElementById("authenticatorData").value = base64url.encode(credential.response.authenticatorData);
        document.getElementById("signature").value = base64url.encode(credential.response.signature);
        document.getElementById("loginClientExtensions").value = JSON.stringify(credential.getClientExtensionResults());
        document.getElementById("login-form").submit();
    } catch (error) {
        console.error("Error:%s, Message:%s", error.name, error.message);
    }
});
```
</details>
