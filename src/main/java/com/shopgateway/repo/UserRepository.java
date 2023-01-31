package com.shopgateway.repo;

import com.shopgateway.domain.Customer;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
//import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;

public interface UserRepository {//extends ReactiveCrudRepository<Customer, String> {
   // Mono<UserDetails> findByUsername(String username);
}