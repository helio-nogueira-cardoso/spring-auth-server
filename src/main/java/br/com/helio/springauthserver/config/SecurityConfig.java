package br.com.helio.springauthserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /*
     * Defines the security configuration for the Authorization Server.
     *
     * This security filter chain ensures that authentication and authorization
     * mechanisms are properly enforced for OAuth2 and OpenID Connect (OIDC) flows.
     * It also configures how authentication failures are handled.
     *
     * The returned bean is responsible for securing the authorization server endpoints,
     * validating access tokens, and managing authentication entry points.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity httpSecurity)
            throws Exception {
        OAuth2AuthorizationServerConfigurer oAuth2AuthorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        httpSecurity
                /*
                 * Applies security rules only to the Authorization Server endpoints.
                 *
                 * The method `getEndpointsMatcher()` retrieves the request matchers for all
                 * OAuth2 and OpenID Connect (OIDC) endpoints managed by the Authorization Server.
                 *
                 * This ensures that security configurations in this filter chain apply only to
                 * the relevant endpoints, preventing conflicts with other security settings.
                 *
                 * By using `getEndpointsMatcher()`, there is no need to manually specify each
                 * endpoint (e.g., "/oauth2/token", "/oauth2/authorize"), making the configuration
                 * more maintainable and aligned with the Authorization Server's default behavior.
                 */
                .securityMatcher(oAuth2AuthorizationServerConfigurer.getEndpointsMatcher())
                /*
                 * Configures the Resource Server to accept JWT tokens.
                 * This means that protected endpoints will require a valid JWT token
                 * for authentication and authorization.
                 * The `Customizer.withDefaults()` applies Spring Security's default JWT settings.
                 */
                .oauth2ResourceServer(
                        oauth2ResourceServerConfigurer ->
                                oauth2ResourceServerConfigurer.jwt(Customizer.withDefaults())
                )

                /*
                 * Applies the Authorization Server configuration to HttpSecurity.
                 * Enables OpenID Connect (OIDC) support, allowing the authorization server
                 * to handle authentication using OIDC.
                 * The `Customizer.withDefaults()` applies Spring Security's default OIDC settings.
                 */
                .with(oAuth2AuthorizationServerConfigurer,
                        RefToOAuth2AuthorizationServerConfigurer ->
                                RefToOAuth2AuthorizationServerConfigurer.oidc(Customizer.withDefaults())
                )
                /*
                 * Configures exception handling for authentication failures.
                 * If an unauthenticated user tries to access a protected resource,
                 * they will be redirected to the login page ("/login").
                 * This ensures that users are properly guided to authenticate
                 * before accessing secured endpoints.
                 */
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login")
                        )
                );

        return httpSecurity.build();
    }

    /*
     * Defines the default security configuration for the application.
     *
     * This security filter chain ensures that all incoming requests require authentication
     * and provides a mechanism for users to log in.
     *
     * The returned bean is responsible for enforcing authentication rules
     * and handling user login functionality.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /*
     * This method defines an in-memory user details service with a default user.
     * It is primarily used to provide a basic authentication mechanism for Spring Security.
     * However, it is not necessary for our application's main authentication flow,
     * which is based on the client credentials flow.
     *
     * ### Why is this method unnecessary for our application?
     * Our application is designed to use the **client credentials flow**, which is a type of OAuth2 authentication.
     * In this flow, authentication is performed using client credentials (such as a client ID and secret)
     * rather than individual user credentials. This is typically used for machine-to-machine authentication,
     * where a service authenticates itself rather than a human user logging in.
     *
     * Since our application does not require user-based authentication, defining a `UserDetailsService`
     * with a default user is not needed for our actual security flow. However, we are including it here
     * as a **baseline configuration** for Spring Security, ensuring that the application has a minimal
     * authentication setup in place.
     *
     * ### Could we avoid implementing this method?
     * Yes, in a stricter implementation, we could **completely remove this method** to avoid unnecessary
     * user-based authentication logic. However, we are providing it here for **completeness** and to
     * demonstrate a basic Spring Security setup. This can be useful for developers who are new to Spring Security
     * and want to understand how user authentication works before transitioning to more advanced authentication flows.
     *
     * ### Security concerns in production environments
     * In this example, we are defining a user with a hardcoded username (`"user"`) and password (`"password"`).
     * This approach is **not secure** and should never be used in a real-world production environment.
     *
     * In production, storing credentials directly in the source code is a major security risk because:
     * - It exposes sensitive information in the codebase, which could be leaked or accessed by unauthorized users.
     * - If the code is stored in a version control system (e.g., Git), the credentials could be exposed to anyone
     *   with access to the repository.
     * - Hardcoded credentials cannot be easily rotated or updated without modifying the source code.
     *
     * Instead, in a real-world scenario, credentials should be stored securely using:
     * - **Environment variables**: Store sensitive information outside the codebase.
     * - **Secrets management tools**: Use services like AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault.
     * - **External authentication providers**: Use OAuth2, OpenID Connect, or an identity provider (e.g., Keycloak, Okta, Auth0).
     *
     * ### Summary
     * - This method provides a basic in-memory authentication setup.
     * - It is **not required** for our client credentials flow but is included as a baseline for Spring Security.
     * - In a stricter implementation, we could **remove this method** entirely.
     * - Hardcoding credentials in the source code is **not secure** and should be avoided in production.
     * - Secure alternatives include environment variables, secrets managers, and external authentication providers.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    /*
     * This method defines a repository for registered OAuth2 clients.
     * It is responsible for storing client details such as client ID, secret, authentication methods,
     * authorization grant types, and scopes.
     *
     * ### Why is this method necessary?
     * In an OAuth2 authorization server, clients (such as applications or services) must be registered
     * so they can authenticate and request access tokens. This method registers a client with different
     * authentication flows, including the **Client Credentials Flow**, which is the focus of our application.
     *
     * ### How does this method configure the Client Credentials Flow?
     * The following line explicitly enables the **Client Credentials Flow**:
     * ```java
     * .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
     * ```
     * In this flow, the client (e.g., a backend service) authenticates itself using its **client ID** and **client secret**
     * without requiring user interaction. This is useful for machine-to-machine authentication, where a service
     * needs to access protected resources on behalf of itself rather than a user.
     *
     * ### Why are other grant types included?
     * - **Authorization Code Flow (`AUTHORIZATION_CODE`)**: This is typically used for user authentication,
     *   where a user logs in and grants permissions to the client. While not necessary for our client credentials flow,
     *   it is included here as a baseline configuration.
     * - **Refresh Token Flow (`REFRESH_TOKEN`)**: Allows clients to obtain a new access token without requiring
     *   the user to log in again. This is useful for long-lived sessions.
     *
     * ### Why are we using an in-memory repository?
     * In this implementation, we are using an **in-memory repository**:
     * ```java
     * return new InMemoryRegisteredClientRepository(oidcClient);
     * ```
     * This means that registered clients are stored in memory and will be lost when the application restarts.
     * This approach is useful for development and testing but **not recommended for production**.
     *
     * ### How could we configure a JDBC-based repository for production?
     * In a real-world scenario, client details should be stored in a **persistent database**.
     * Spring Security provides a `JdbcRegisteredClientRepository` that allows storing clients in a relational database.
     *
     * Example of configuring a JDBC-based repository:
     * ```java
     * @Bean
     * public RegisteredClientRepository registeredClientRepository(DataSource dataSource) {
     *     JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource));
     *     return repository;
     * }
     * ```
     * This approach ensures that registered clients persist across application restarts and can be managed dynamically.
     *
     * ### Summary
     * - This method registers an OAuth2 client with different authentication flows.
     * - The **Client Credentials Flow** is explicitly enabled for machine-to-machine authentication.
     * - We are using an **in-memory repository**, which is suitable for development but **not for production**.
     * - In production, a **JDBC-based repository** should be used to store client details in a database.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("oidc-client")
                /*
                 * The `{noop}` prefix indicates that the client secret is stored in plain text
                 * without any encoding. This is useful for testing purposes but should never
                 * be used in production.
                 *
                 * In a real-world scenario, passwords should be securely hashed using a strong
                 * algorithm like BCrypt (`{bcrypt}`) to protect sensitive credentials.
                 */
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // Here we set up Client Credentials Flow (our focus):
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }

    /*
     * This method configures the JSON Web Key (JWK) source for the authorization server.
     * JWK is used to securely sign and verify JWT (JSON Web Tokens), ensuring that tokens
     * issued by the server can be validated by clients.
     *
     * ### Why is this method necessary?
     * In an OAuth2 authorization server, access tokens (typically JWTs) need to be **digitally signed**
     * to ensure their authenticity and integrity. Clients and resource servers use the public key
     * to verify that a token was issued by a trusted source.
     *
     * This method generates an **RSA key pair** (public and private keys) and registers it as a JWK source.
     * - The **private key** is used to sign JWTs.
     * - The **public key** is used by clients to verify the signature of JWTs.
     *
     * ### How does this method work?
     * 1. **Generate an RSA key pair**:
     *    ```java
     *    KeyPair keyPair = generateRsaKey();
     *    ```
     *    This creates a new RSA key pair (public and private keys).
     *
     * 2. **Extract the public and private keys**:
     *    ```java
     *    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
     *    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
     *    ```
     *    These keys will be used for signing and verifying JWTs.
     *
     * 3. **Create an RSA JWK (JSON Web Key)**:
     *    ```java
     *    RSAKey rsaKey = new RSAKey.Builder(publicKey)
     *            .privateKey(privateKey)
     *            .keyID(UUID.randomUUID().toString())
     *            .build();
     *    ```
     *    This wraps the RSA key pair into a JWK format, which is a standard way to represent cryptographic keys.
     *
     * 4. **Create a JWK set and return it as an immutable source**:
     *    ```java
     *    JWKSet jwkSet = new JWKSet(rsaKey);
     *    return new ImmutableJWKSet<>(jwkSet);
     *    ```
     *    This ensures that the key set is available for JWT signing and verification.
     *
     * ### Security Considerations
     * - **Key persistence**: In this implementation, the RSA key pair is generated **in-memory** at runtime.
     *   This means that every time the application restarts, a new key pair is created, invalidating previously issued tokens.
     * - **Production alternative**: In a real-world scenario, the RSA key pair should be **persisted** in a secure location,
     *   such as a **database**, **HSM (Hardware Security Module)**, or **a secure file storage**.
     * - **Key rotation**: Regular key rotation should be implemented to enhance security.
     *
     * ### Summary
     * - This method generates an **RSA key pair** for signing and verifying JWTs.
     * - The **private key** is used to sign tokens, and the **public key** is used for verification.
     * - The key is stored **in-memory**, which is suitable for development but **not for production**.
     * - In production, keys should be **persisted securely** and **rotated periodically**.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // Generate a new RSA key pair (public and private keys)
        KeyPair keyPair = generateRsaKey();

        // Extract the public and private keys from the key pair
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // Create an RSA JWK (JSON Web Key) with a unique key ID
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        // Create a JWK set containing the RSA key
        JWKSet jwkSet = new JWKSet(rsaKey);

        // Return an immutable JWK source for JWT signing and verification
        return new ImmutableJWKSet<>(jwkSet);
    }

    /*
     * Generates a new RSA key pair (public and private keys) for cryptographic operations.
     * This key pair is used to sign and verify JWTs in the authorization server.
     *
     * ### Key Details:
     * - Uses **RSA** algorithm with a **2048-bit key size** (secure and efficient).
     * - The **private key** is used to sign tokens, while the **public key** is used for verification.
     * - Keys are **generated in-memory** and **not persisted**, meaning they are lost on application restart.
     *
     * ### Production Considerations:
     * - In a real-world scenario, keys should be **stored securely** (e.g., database, secure file, HSM).
     * - Implement **key rotation** to enhance security and prevent long-term exposure.
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            // Create an RSA key pair generator
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            // Set the key size to 2048 bits (secure and efficient)
            keyPairGenerator.initialize(2048);

            // Generate the RSA key pair (public and private keys)
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            // Throw an exception if key generation fails
            throw new IllegalStateException(ex);
        }

        // Return the generated RSA key pair
        return keyPair;
    }

    /*
     * Configures the **JWT Decoder** for the authorization server.
     * This component is responsible for **validating and decoding JWTs** (JSON Web Tokens)
     * issued by the server.
     *
     * ### Why is this method necessary?
     * In an OAuth2 authorization server, access tokens are typically issued as **JWTs**.
     * When a client or resource server receives a JWT, it needs to verify its authenticity
     * before granting access to protected resources.
     *
     * The **JwtDecoder** is responsible for:
     * - **Verifying the JWT signature**: Ensuring the token was issued by a trusted source.
     * - **Validating token claims**: Checking expiration time, issuer, audience, etc.
     * - **Decoding the JWT payload**: Extracting user or client information.
     *
     * ### How does this method work?
     * - It **receives a JWK source** (`JWKSource<SecurityContext> jwkSource`), which provides
     *   the public key needed to verify JWT signatures.
     * - It delegates the creation of the **JwtDecoder** to Spring Security's
     *   `OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)`, which automatically
     *   configures a decoder that can validate JWTs using the provided JWK source.
     *
     * ### Security Considerations
     * - **Signature verification**: The decoder ensures that only tokens signed with the
     *   server's private key are accepted.
     * - **Token expiration**: Expired tokens are automatically rejected.
     * - **Issuer validation**: The decoder can be configured to accept tokens only from
     *   a specific issuer.
     *
     * ### Summary
     * - This method **configures the JwtDecoder**, which validates and decodes JWTs.
     * - It uses the **JWK source** to verify token signatures.
     * - It ensures that only valid and trusted JWTs are accepted.
     * - This is a critical security component in an OAuth2 authorization server.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /*
     * Creates and provides an instance of {@link AuthorizationServerSettings}.
     *
     * This method initializes the authorization server settings using the default builder,
     * which implicitly configures several OAuth 2.0 and OpenID Connect (OIDC) endpoints.
     * These endpoints are essential for handling authentication, authorization, and token management.
     *
     * ### Configured Endpoints:
     * - **Authorization Endpoint (`/oauth2/authorize`)**: Handles user authentication and authorization requests.
     * - **Device Authorization Endpoint (`/oauth2/device_authorization`)**: Supports OAuth 2.0 Device Authorization Grant for devices without a browser.
     * - **Device Verification Endpoint (`/oauth2/device_verification`)**: Allows users to verify and approve device-based authorization requests.
     * - **Token Endpoint (`/oauth2/token`)**: Issues access tokens after successful authentication.
     * - **Token Introspection Endpoint (`/oauth2/introspect`)**: Allows resource servers to validate access tokens.
     * - **Token Revocation Endpoint (`/oauth2/revoke`)**: Enables clients to revoke access or refresh tokens.
     * - **JWK Set Endpoint (`/oauth2/jwks`)**: Provides JSON Web Key Set (JWKS) for verifying JWT signatures.
     * - **OIDC Logout Endpoint (`/connect/logout`)**: Supports OpenID Connect (OIDC) logout functionality.
     * - **OIDC User Info Endpoint (`/userinfo`)**: Returns user profile information for authenticated users.
     * - **OIDC Client Registration Endpoint (`/connect/register`)**: Allows dynamic client registration in an OpenID Connect environment.
     *
     * ### Why is this important?
     * This method ensures that the authorization server is properly configured with the necessary endpoints
     * to support OAuth 2.0 and OIDC flows. It simplifies the setup process by using default values,
     * making it easier for developers to get started with authentication and authorization.
     *
     * @return an instance of {@link AuthorizationServerSettings} with default endpoint configurations.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

}