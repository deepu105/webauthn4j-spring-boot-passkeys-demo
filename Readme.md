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

The endpoints are configured in `src/main/java/com/example/demo/web/WebAuthnSampleController.java`. The `/` and `/login` endpoints are quite simple and self-explanatory. The `/signup` endpoint handles the WebAuthn registration request using WebAuthn4j. The request is first validated using `WebAuthnRegistrationRequestValidator` and then the authenticator is created using `WebAuthnAuthenticatorManager`.

### Client-side configuration

The file `src/main/resources/templates/login.html` handles login and sign-up. The login button will invoke the `navigator.credentials.get()` API and the register button will invoke the `navigator.credentials.create()` API. The buttons submit the corresponding forms with the input data in them. All inputs except the `username` field are hidden as their data will be set using JavaScript.

WebAuthn4j exposes `/webauthn/attestation/options` endpoint in the application to fetch the registration options. Some of the option parameters need to be decoded from base64URL. The [base64url-arraybuffer](https://github.com/deepu105/base64url-arraybuffer) library is used for this. The options are then passed to the `navigator.credentials.create()` API. The response from the API is then updated to the form fields and submitted to the `/signup` endpoint.

WebAuthn4j exposes `/webauthn/assertion/options` endpoint in the application to fetch the authentication options. Some of the option parameters need to be decoded from base64URL. The options are then passed to the `navigator.credentials.get()` API. The response from the API is then updated to the form fields and submitted to the `/login` endpoint.
