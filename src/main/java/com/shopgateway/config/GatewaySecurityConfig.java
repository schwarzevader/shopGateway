package com.shopgateway.config;

import com.shopgateway.config.ReactiveUserDetailsServiceImp;
import com.shopgateway.domain.Customer;
import com.shopgateway.service.CustomerInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
//import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
//import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.socket.server.support.WebSocketHandlerAdapter;
import reactor.core.publisher.Mono;

import javax.ws.rs.HttpMethod;
import java.util.Map;

import static org.springframework.http.HttpMethod.POST;

@Configuration
//@EnableWebSecurity
@EnableWebFluxSecurity
//@EnableReactiveMethodSecurity
public class GatewaySecurityConfig  {//extends WebSecurityConfigurerAdapter{


//    @Autowired
//    private UserDetailsService userDetailsService ;

    @Autowired
    private CustomerInfoService userRepo;
////    @Autowired
////    private ReactiveUserDetailsServiceImp reactiveUserDetailsService;
//
//    @Autowired
//    private BCryptPasswordEncoder passwordEncoder ;

//    @Bean
//    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) throws Exception {
//        http.authorizeExchange()
//                .pathMatchers("/")
//                .authenticated()
//                .and()
//                .formLogin();
//        return http.build();
//    }

//    @Bean
//    ReactiveJwtDecoder jwtDecoder() {
//        //return ReactiveJwtDecoders.fromOidcIssuerLocation("http://localhost:8080/realms/spring-microservices");
//        return ReactiveJwtDecoders.fromOidcIssuerLocation("http://localhost:8080/auth/realms/spring-microservice");
//    }


//
//    @Bean
//    public ClientRegistration keycloakClientRegistration(){
//        return ClientRegistration.withRegistrationId("keycloak") // registration_id
//                .clientId("shopGateway")
//                .clientSecret("nxEEYS7EvN8WEHIK8ljqP83JYdCJFEBy")
//                .scope("openid")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//
//                // {baseUrl}/login/oauth2/code/{registration_id}
//                .redirectUri("http://localhost:8073/*")
//                .authorizationUri("http://localhost:8080/auth/realms/master/protocol/openid-connect/auth")
//                .tokenUri("http://localhost:8080/auth/realms/master/protocol/openid-connect/token")
//                .userInfoUri("http://localhost:8080/auth/realms/master/protocol/openid-connect/userinfo")
//                .jwkSetUri("http://localhost:8080/auth/realms/master/protocol/openid-connect/certs")
//                .userNameAttributeName(IdTokenClaimNames.SUB)
//                .clientName("Keycloak")
//                .tokenUri("http://localhost:8080/auth/realms/master-realm/protocol/openid-connect/token")
//                .issuerUri("http://localhost:8080/realms/master")
//                .build();
//    }
//
//
//    @Bean
//    public WebSocketHandlerAdapter handlerAdapter() {
//        return new WebSocketHandlerAdapter();
//    }


    @Bean
    public SecurityWebFilterChain mySecurityWebFilterChain(ServerHttpSecurity http){
//        http.csrf()
//                .disable()
//                .authorizeExchange(exchange-> exchange.pathMatchers("/eureka/**").permitAll()
////                        .pathMatchers(HttpMethod.POST,"/shop/products/new").permitAll()
////                        .pathMatchers(HttpMethod.POST,"/shop/products/new/**").permitAll()
////                        .pathMatchers(HttpMethod.POST,"/shop/**").permitAll()
////                        .pathMatchers(HttpMethod.POST,"/**").permitAll()
////                        .pathMatchers(HttpMethod.POST,"http://localhost:8073/shop/products/new").permitAll()
////                        .pathMatchers(HttpMethod.POST,"/posts/**").permitAll()
////                        .pathMatchers(HttpMethod.POST,"http://localhost:8180/products/new").permitAll()
//
//                        //.pathMatchers(HttpMethod.POST).permitAll()
//                        .anyExchange()
//                        .authenticated().and()
//                        .formLogin())//;
//                .oauth2ResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec::jwt);
//
//        return http.build();
        //-------
        http
                .csrf().disable()
                .authorizeExchange()
                .pathMatchers("/headerrouting/**").permitAll()
                .pathMatchers("/actuator/**").permitAll()
                .pathMatchers("/eureka-server/**").permitAll()
                .pathMatchers("/eureka/**").permitAll()
                .pathMatchers("/oauth/**").permitAll()
                .pathMatchers("/config/**").permitAll()
//                .pathMatchers(HttpMethod.POST,"/shop/products/new").permitAll()
//                .pathMatchers(HttpMethod.POST,"/shop/products/new/**").permitAll()
//                .pathMatchers(HttpMethod.POST,"/products/new").permitAll()
//                .pathMatchers("/products/new").permitAll()
//                .pathMatchers(HttpMethod.POST,"/products/new/**").permitAll()
//                .pathMatchers(HttpMethod.POST,"/shop/**").permitAll()
//                .pathMatchers(HttpMethod.POST,"/**").permitAll()
//                .pathMatchers(HttpMethod.GET,"/**").permitAll()
//                .pathMatchers(HttpMethod.POST,"http://localhost:8073/shop/products/new").permitAll()
//                .pathMatchers(HttpMethod.POST,"http://localhost:8073/products/new").permitAll()
//                .pathMatchers(HttpMethod.POST,"http://localhost:8180/products/new").permitAll()
//                .pathMatchers(HttpMethod.POST).permitAll()
                .pathMatchers(POST).permitAll()
                .anyExchange().authenticated()
                .and()
                .oauth2ResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec::jwt);
        return http.build();
    }

//-----
//    @Bean
//    public ReactiveUserDetailsService userDetailsService() {
//        return new ReactiveUserDetailsService() {
//            @Override
//            public Mono<UserDetails> findByUsername(String username) {
//                return userRepo.findByUN(username)
//                        .map(Customer::toUserDetails);
//            }
//        };
//    }
//-----


//    @Bean
//    public ReactiveUserDetailsService userDetailsService() {
//        return (username) -> userRepo.findByUsername(username).cast(UserDetails.class);
//    }

//    @Bean
//    public ReactiveAuthenticationManager authenticationManager() {
//        UserDetailsRepositoryReactiveAuthenticationManager manager = new UserDetailsRepositoryReactiveAuthenticationManager((ReactiveUserDetailsService) userDetailsService);
//        manager.setPasswordEncoder(passwordEncoder);
//        return manager;
//    }

//    @Bean
//    public ReactiveUserDetailsService userDetailsService(AccountDAO accountDAO, Scheduler scheduler) {
//        return username -> {
//            return Mono.defer(() -> {
//                return Mono.justOrEmpty(accountDAO.accountByUsername(username))
//                        .map(acct -> {
//                            return User.withUsername(username)
//                                    .password(acct.getPassword())
//                                    .roles("MEMBER")
//                                    .build();
//                        });
//
//            }).subscribeOn(scheduler);
//        };
//    }

//--------
//    @Bean
//    public ReactiveUserDetailsService userDetailsService() {
//        return username -> {
//            return Mono.defer(() -> {
//                return Mono.justOrEmpty(userRepo.findByUsername(username))
//                        .map(acct -> {
//                            return User.withUsername(username)
//                                    .password(acct.getPassword())
//                                    .roles("MEMBER")
//                                    .build();
//                        });
//
//            });//.subscribeOn(scheduler);
//        };
//    }
///--------

//    @Bean
//    public ReactiveAuthenticationManager authenticationManager() {
////        if (this.authenticationManager != null) {
////            return this.authenticationManager;
////        }
//        if (this.reactiveUserDetailsService != null) {
//            UserDetailsRepositoryReactiveAuthenticationManager manager =
//                    new UserDetailsRepositoryReactiveAuthenticationManager(this.reactiveUserDetailsService);
//            if (this.passwordEncoder != null) {
//                manager.setPasswordEncoder(this.passwordEncoder);
//            }
//            manager.setUserDetailsPasswordService((ReactiveUserDetailsPasswordService) this.passwordEncoder);
//            return manager;
//        }
//        return null;
//    }

//    @Bean
//    public MapReactiveUserDetailsService reactiveUserDetailsService() {
//
//        UserDetails userDetails =
//        return new MapReactiveUserDetailsService();
//    }

//    private Mono<AuthorizationDecision> currentUserMatchesPath(Mono<Authentication> authentication, AuthorizationContext context) {
//        return authentication
//                .map(a -> context.getVariables().get("user").equals(a.getName()))
//                .map(AuthorizationDecision::new);
//    }

//    @Bean
//    public DaoAuthenticationProvider authenticationProvider(){
//        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
//        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
//        daoAuthenticationProvider.setUserDetailsService((UserDetailsService) userDetailsService);
//        //daoAuthenticationProvider.setUserDetailsService(userDetailsService);
//        return daoAuthenticationProvider;
//    }


//    @Bean
//    public MapReactiveUserDetailsService reactiveUserDetailsService() {
//        UserDetails userAdmin = User.withDefaultPasswordEncoder()
//                .username("admin")
//                .password("admin")
//                .roles("ADMIN")
//                .build();
//        UserDetails userUser = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("user")
//                .roles("USER")
//                .build();
//        return new MapReactiveUserDetailsService(userAdmin, userUser);
//    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
//    }
//
//
//    @Override
//    @Bean
//    public AuthenticationManager authenticationManagerBean() throws  Exception{
//        return super.authenticationManagerBean();
//    }




//    @Bean
//    public ReactiveJwtDecoder jwtDecoder() {
//        return ReactiveJwtDecoders.fromIssuerLocation(issuerUri);
//    }

//    @Bean
//    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, ServerLogoutSuccessHandler handler) {
//        http
//                .authorizeExchange()
//                .pathMatchers("/actuator/**", "/","/logout.html")
//                .permitAll()
//                .and()
//                .authorizeExchange()
//                .anyExchange()
//                .authenticated()
//                .and()
//                .oauth2Login() // to redirect to oauth2 login page.
//                .and()
//                .logout()
//                .logoutSuccessHandler(handler);
//        return http.build();
//    }
//
//    @Bean
//    public ServerLogoutSuccessHandler keycloakLogoutSuccessHandler(ReactiveClientRegistrationRepository repository) {
//
//        OidcClientInitiatedServerLogoutSuccessHandler oidcLogoutSuccessHandler =
//                new OidcClientInitiatedServerLogoutSuccessHandler(repository);
//
//        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/logout.html");
//
//        return oidcLogoutSuccessHandler;
//    }





//    private HandlerExceptionResolver resolver;
//
//    @Autowired
//    public void setResolver(@Qualifier("handlerExceptionResolver")HandlerExceptionResolver resolver) {
//        this.resolver = resolver;
//    }



//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
////      customAuthenticationFilter.setRememberMeServices();
//        customAuthenticationFilter.setSuccessHandler(new CustomSuccessHandler());
//
//
//
//        //customAuthenticationFilter.setFilterProcessesUrl("/home/login/");
//        //customAuthenticationFilter.setFilterProcessesUrl("/login");
//
//        //AuthenticationFilterCustom authenticationFilterCustom = new AuthenticationFilterCustom();
//        //authenticationFilterCustom.setFilterProcessesUrl("/home/login");
//        //http.csrf().disable().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//        //http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
//        http.cors();
//        http.csrf().disable();
//
//
//        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//
//        http.addFilter(customAuthenticationFilter );
//        http.addFilterBefore(new CustomAuthorizationFilter() , UsernamePasswordAuthenticationFilter.class);
//        //http.addFilterAfter(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
//
//        http.authorizeRequests().antMatchers("/home/login/**").permitAll();
//
//
//        http.authorizeRequests().antMatchers( "/js/**", "/css/**").permitAll();
//        //http.authorizeRequests().antMatchers(POST ,"/home/login/").permitAll();
//        //http.authorizeRequests().antMatchers(GET ,"/home/login/").permitAll();
//
//        http.authorizeRequests().antMatchers(POST,"/registration").permitAll();
//        http.authorizeRequests().antMatchers("/registration").permitAll();
//        http.authorizeRequests().antMatchers(POST ,"/login/**").permitAll();
//        http.authorizeRequests().antMatchers(POST ,"/login").permitAll();
//        http.authorizeRequests().antMatchers(POST ,"/order/new").permitAll();
//        http.authorizeRequests().antMatchers("/login/**").permitAll();
//        //http.authorizeRequests().antMatchers(GET ,"/login").permitAll();
//
//        http.authorizeRequests().antMatchers(GET ,"/singin").permitAll();
////        http.authorizeRequests().antMatchers(GET ,"templates/**").permitAll();
////        http.authorizeRequests().antMatchers(GET ,"/fragments/**").permitAll();
//        http.authorizeRequests().antMatchers(POST ,"/singin").permitAll();
//
//        http.authorizeRequests().antMatchers(GET , "/users/**").hasAnyAuthority("ROLE_USER");
//        http.authorizeRequests().antMatchers(GET , "/admins/**").hasAnyAuthority("ROLE_ADMIN");
//
//        http.authorizeRequests().antMatchers().permitAll();
//        http.authorizeRequests().antMatchers("/").permitAll();
//        http.authorizeRequests().antMatchers("/**").permitAll();
//        http.authorizeRequests().anyRequest().authenticated();
//        //http.authorizeRequests().and().formLogin().successForwardUrl("http://localhost:8080/h");
//
//        http.authorizeRequests().and()
//                .logout()
//                .logoutUrl("/logout")
//                .addLogoutHandler(new CustomLogoutHandler())
//                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
//                .permitAll();
//
//        http.headers().frameOptions().sameOrigin();
//        //http.oauth2Login();
//        //http.authorizeRequests().and().formLogin().and().httpBasic();
//
//
//
//
//    }


//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(Arrays.asList("*"));
//        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
//        configuration.setAllowedHeaders(Arrays.asList("authorization", "content-type", "x-auth-token"));
//        configuration.setExposedHeaders(Arrays.asList("x-auth-token"));
//        configuration.setExposedHeaders(Arrays.asList(HttpHeaders.AUTHORIZATION));
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//    }


}
