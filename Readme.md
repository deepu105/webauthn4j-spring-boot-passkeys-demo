# Passkeys with Spring Boot and WebAuthn4j

This is a bare-bones Spring Boot web application with [WebAuthn4j](https://github.com/webauthn4j/webauthn4j-spring-security) to demonstrate passkeys with WebAuthn.

The user details are stored in memory.

## Why use passkeys?

Passkeys are FIDO credentials that are discoverable by browsers or housed in hardware authenticators like your mobile device, laptop, or security keys for passwordless authentication. Passkeys replace passwords with cryptographic key pairs for phishing-resistant sign-in security and an improved user experience. The cryptographic keys are used from end-user devices (computers, phones, or security keys) for user authentication. Any passwordless FIDO credential is a passkey.

We believe that passkeys offer a viable alternative to passwords for consumer applications, and we are committed to promoting this much-needed industry shift by making it easy for you, developers, and builders to offer that experience to your users.

### Running this app

Clone this repo

```shell
git clone https://github.com/deepu105/webauthn4j-spring-boot-passkeys-demo
```

Start the app.

```shell
./gradlew bootRun
```

Visit [http://localhost:8080]. Click on **Sign Up** and create a new user. You will be prompted to sign up with a passkey.
